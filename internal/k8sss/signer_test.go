package k8sss

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startAgent serves an SSH agent holding one key and returns its socket path.
func startAgent(t *testing.T, key crypto.Signer, comment string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k8sss-agent")
	if err != nil {
		t.Fatalf("creating agent directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")
	if len(socket) > 100 {
		t.Skip("temporary directory leaves no room for a unix socket path")
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: key, Comment: comment}); err != nil {
		t.Fatalf("adding key to the agent: %v", err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	return socket
}

// testCSR builds a certificate request for username the way renewCertificate
// does, around a fresh key.
func testCSR(t *testing.T, username string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	csr, err := x509util.CreateCertificateRequest(username, []string{username}, key)
	if err != nil {
		t.Fatalf("creating csr: %v", err)
	}
	return csr
}

func testKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating an ECDSA key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an Ed25519 key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an RSA key: %v", err)
	}
	return map[string]crypto.Signer{"ecdsa": ecKey, "ed25519": edKey, "rsa": rsaKey}
}

// An SSH agent hashes the message itself and answers ECDSA in SSH wire format,
// and signs RSA with the legacy SHA-1 algorithm unless asked otherwise. None
// of that is what JWS wants, so the token is parsed and verified here by
// go-jose, independently of the code that produced it.
func TestSSHAgentTokensVerify(t *testing.T) {
	for name, key := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			const comment = "tester@workstation"
			t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))

			signing, err := openSigningKey("sshagentkms:" + comment)
			if err != nil {
				t.Fatalf("openSigningKey: %v", err)
			}
			defer signing.Close()

			ott, err := signing.token("https://nas:9000", "system:admin", testCSR(t, "system:admin"))
			if err != nil {
				t.Fatalf("token: %v", err)
			}
			jws, err := jose.ParseJWS(ott)
			if err != nil {
				t.Fatalf("the token is not a valid JWS: %v", err)
			}
			if _, err := jws.Verify(key.Public()); err != nil {
				t.Errorf("the token does not verify against the key: %v", err)
			}
			if got := jws.Signatures[0].Header.Algorithm; got != string(signing.alg) {
				t.Errorf("algorithm: header says %q, key says %q", got, signing.alg)
			}
		})
	}
}

// The JWK provisioner is named after its key's thumbprint, so the issuer claim
// and the kid header both have to carry it.
func TestSSHAgentTokenIssuerIsTheThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))

	signing, err := openSigningKey("sshagentkms:" + comment)
	if err != nil {
		t.Fatalf("openSigningKey: %v", err)
	}
	defer signing.Close()

	want, err := jose.Thumbprint(&jose.JSONWebKey{Key: key.Public()})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	csr := testCSR(t, "system:admin")
	ott, err := signing.token("https://nas:9000", "system:admin", csr)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	jws, err := jose.ParseJWS(ott)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if got := jws.Signatures[0].Header.KeyID; got != want {
		t.Errorf("kid header: got %q, want %q", got, want)
	}
	payload, err := jws.Verify(key.Public())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var claims struct {
		Issuer   string   `json:"iss"`
		Subject  string   `json:"sub"`
		Audience string   `json:"aud"`
		SANS     []string `json:"sans"`
		ID       string   `json:"jti"`
		CNF      struct {
			Fingerprint string `json:"x5rt#S256"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing claims: %v", err)
	}
	if claims.Issuer != want {
		t.Errorf("iss: got %q, want %q", claims.Issuer, want)
	}
	if claims.Subject != "system:admin" {
		t.Errorf("sub: got %q", claims.Subject)
	}
	if claims.Audience != "https://nas:9000/1.0/sign" {
		t.Errorf("aud: got %q", claims.Audience)
	}
	if len(claims.SANS) != 1 || claims.SANS[0] != "system:admin" {
		t.Errorf("sans: got %q", claims.SANS)
	}
	if claims.ID == "" {
		t.Error("jti is empty, so the CA cannot reject a replayed token")
	}
	// What step-ca's JWK provisioner compares against the CSR it is asked to
	// sign, so a leaked token only yields a certificate for this key.
	sum := sha256.Sum256(csr.Raw)
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); claims.CNF.Fingerprint != want {
		t.Errorf("cnf x5rt#S256: got %q, want %q", claims.CNF.Fingerprint, want)
	}
}

// Each attempt needs its own token, since the CA remembers the ones it has
// already seen.
func TestTokensAreNotReused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
	signing, err := openSigningKey("sshagentkms:" + comment)
	if err != nil {
		t.Fatalf("openSigningKey: %v", err)
	}
	defer signing.Close()

	csr := testCSR(t, "system:admin")
	first, err := signing.token("https://nas:9000", "system:admin", csr)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	second, err := signing.token("https://nas:9000", "system:admin", csr)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if first == second {
		t.Error("two tokens came out identical")
	}
}

func TestSSHECDSAToJWSPadsToTheCurveWidth(t *testing.T) {
	// A leading bit set in r forces the SSH mpint encoding to prepend a 0x00
	// byte, and a tiny s has to be padded out to the full coordinate width.
	r := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 32))
	s := big.NewInt(1)
	blob := ssh.Marshal(struct{ R, S *big.Int }{r, s})

	got, err := sshECDSAToJWS(blob, 32)
	if err != nil {
		t.Fatalf("sshECDSAToJWS: %v", err)
	}
	want := make([]byte, 64)
	r.FillBytes(want[:32])
	s.FillBytes(want[32:])
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestSSHECDSAToJWSRejectsOversizedComponents(t *testing.T) {
	tooBig := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 33))
	blob := ssh.Marshal(struct{ R, S *big.Int }{tooBig, big.NewInt(1)})
	if _, err := sshECDSAToJWS(blob, 32); err == nil {
		t.Error("expected an error for a component wider than the curve")
	}
}

func TestSSHECDSAToJWSRejectsGarbage(t *testing.T) {
	if _, err := sshECDSAToJWS([]byte{0x01, 0x02}, 32); err == nil {
		t.Error("expected an error for a malformed signature blob")
	}
}
