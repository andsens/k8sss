package k8sss

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/utils/cautils"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
)

// The deployment's ca.json issues 30 minute certificates and client.tpl is what
// turns the token's subject and groups into the client's identity. Both are
// mirrored here, the template by pointing at the file that is actually
// deployed.
const (
	clientTemplate      = "../../deploy/base/client.tpl"
	certificateDuration = 30 * time.Minute
)

// startRealCA runs step-ca's own authority and HTTP API in process. Where the
// stand-in CA in cert_test.go only checks what it was told to, this exercises
// the real provisioner lookup, audience matching, token replay database, SAN
// validators and certificate templating.
func startRealCA(t *testing.T, testCA *testCA, authorized crypto.PublicKey) string {
	t.Helper()
	jwk := &jose.JSONWebKey{Key: authorized}
	thumbprint, err := jose.Thumbprint(jwk)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	jwk.KeyID = thumbprint

	minimum := provisioner.Duration{Duration: time.Minute}
	maximum := provisioner.Duration{Duration: certificateDuration}
	disableRenewal := true
	auth, err := authority.NewEmbedded(
		authority.WithX509RootCerts(testCA.cert),
		authority.WithX509Signer(testCA.cert, testCA.key),
		authority.WithConfig(&config.Config{
			// The audiences the CA accepts are built from these names with the
			// port stripped off, which is why a token for
			// https://127.0.0.1:<port>/1.0/sign is accepted.
			DNSNames: []string{"127.0.0.1"},
			AuthorityConfig: &config.AuthConfig{
				Provisioners: provisioner.List{
					// Named after the key's thumbprint, the way
					// tools/convert-sshkeys.sh names them.
					&provisioner.JWK{
						Type: "JWK",
						Name: thumbprint,
						Key:  jwk,
						Claims: &provisioner.Claims{
							MinTLSDur:      &minimum,
							MaxTLSDur:      &maximum,
							DefaultTLSDur:  &maximum,
							DisableRenewal: &disableRenewal,
						},
						Options: &provisioner.Options{
							X509: &provisioner.X509Options{TemplateFile: clientTemplate},
						},
					},
				},
			},
		}),
	)
	if err != nil {
		t.Fatalf("starting the authority: %v", err)
	}
	t.Cleanup(func() { auth.Shutdown() })

	router := chi.NewRouter()
	api.Route(router)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.ServeHTTP(w, r.WithContext(authority.NewContext(r.Context(), auth)))
	}))
	// step-ca serves TLS with a certificate from the root it issues from,
	// which for k8sss is the Kubernetes client CA.
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{testCA.cert.Raw},
		PrivateKey:  testCA.key,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

func TestCertAgainstTheRealCA(t *testing.T) {
	for name, key := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			const comment = "tester@workstation"
			t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
			testHome(t)

			testCA := newTestCA(t)
			config := realCAConfig(t, testCA, key.Public(), comment)

			out := captureStdout(t, func() {
				if err := Cert(context.Background(), config); err != nil {
					t.Fatalf("Cert: %v", err)
				}
			})
			leaf := credentialLeaf(t, out)

			// client.tpl is what grants cluster-admin, so it is worth checking
			// that the deployed template produced it from the default groups.
			if leaf.Subject.CommonName != "system:admin" {
				t.Errorf("common name: got %q, want system:admin", leaf.Subject.CommonName)
			}
			if !slices.Equal(leaf.Subject.Organization, []string{"system:masters"}) {
				t.Errorf("organization: got %q, want system:masters", leaf.Subject.Organization)
			}
			if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
				t.Errorf("extended key usage: got %v, want client auth only", leaf.ExtKeyUsage)
			}
			// The template names no SANs, so the URI the CSR carried to satisfy
			// the token's sans claim is dropped from the certificate.
			if len(leaf.URIs)+len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
				t.Errorf("the certificate carries SANs: uris=%v dns=%q", leaf.URIs, leaf.DNSNames)
			}

			// step-ca backdates by a minute, so the validity window is the
			// configured duration plus that.
			lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
			if lifetime < certificateDuration || lifetime > certificateDuration+2*time.Minute {
				t.Errorf("lifetime: got %s, want about %s", lifetime, certificateDuration)
			}
			// What the renewal schedule rests on: a fresh certificate is not
			// yet due, and comes due around the half hour's midpoint.
			if pastHalfLife(leaf, time.Now()) {
				t.Error("a freshly issued certificate is already due for renewal")
			}
			due := leaf.NotAfter.Add(-lifetime / 2).Sub(time.Now())
			if due < 10*time.Minute || due > 20*time.Minute {
				t.Errorf("renewal falls due in %s, want roughly 15m", due)
			}

			// It has to chain to the CA the Kubernetes API server trusts.
			roots := x509.NewCertPool()
			roots.AddCert(testCA.cert)
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:     roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}); err != nil {
				t.Errorf("the issued certificate does not chain to the CA: %v", err)
			}
		})
	}
}

// The CA remembers the tokens it has seen, which is why a retry mints a fresh
// one rather than resending the last.
func TestTheRealCARejectsAReplayedToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
	testHome(t)

	testCA := newTestCA(t)
	config := realCAConfig(t, testCA, key.Public(), comment)

	signing, err := openSigningKey(config.KeyURI)
	if err != nil {
		t.Fatalf("openSigningKey: %v", err)
	}
	defer signing.Close()
	client, err := ca.NewClient(config.CAURL, ca.WithRootFile(config.clientCACrt))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	csr := testCSR(t, config.Username)
	ott, err := signing.token(config.CAURL, config.Username, []string{"system:masters"}, csr)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	request := &api.SignRequest{CsrPEM: api.CertificateRequest{CertificateRequest: csr}, OTT: ott}
	if _, err := client.Sign(request); err != nil {
		t.Fatalf("the first use of the token was refused: %v", err)
	}
	if _, err := client.Sign(request); err == nil {
		t.Error("the CA accepted the same token twice")
	}
}

// Whoever gets hold of an unused token can only redeem it for the key it was
// minted for, because the token carries the fingerprint of the CSR.
func TestTheRealCARejectsATokenForAnotherCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
	testHome(t)

	testCA := newTestCA(t)
	config := realCAConfig(t, testCA, key.Public(), comment)

	signing, err := openSigningKey(config.KeyURI)
	if err != nil {
		t.Fatalf("openSigningKey: %v", err)
	}
	defer signing.Close()
	client, err := ca.NewClient(config.CAURL, ca.WithRootFile(config.clientCACrt))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ott, err := signing.token(config.CAURL, config.Username, []string{"system:masters"}, testCSR(t, config.Username))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	other := testCSR(t, config.Username)
	if _, err := client.Sign(&api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: other},
		OTT:    ott,
	}); err == nil {
		t.Error("the CA signed a CSR the token was not minted for")
	}

	// The same request with a token minted for it goes through, so the
	// refusal above was down to the fingerprint.
	ott, err = signing.token(config.CAURL, config.Username, []string{"system:masters"}, other)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if _, err := client.Sign(&api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: other},
		OTT:    ott,
	}); err != nil {
		t.Errorf("the CA refused a token minted for the CSR: %v", err)
	}
}

// sign takes nothing but the key from the request: what the requester puts in
// its subject doesn't reach the certificate, the token's username and groups
// do.
func TestSignAgainstTheRealCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
	testHome(t)
	config := realCAConfig(t, newTestCA(t), key.Public(), comment)
	config.Username, config.Groups = "claude", "claude,readers"

	for name, tc := range map[string]struct {
		subject pkix.Name
		allowed bool
	}{
		"the username as common name":      {pkix.Name{CommonName: "claude"}, true},
		"no common name, asking for admin": {pkix.Name{Organization: []string{"system:masters"}}, true},
		"asking for admin with the name":   {pkix.Name{CommonName: "claude", Organization: []string{"system:masters"}}, true},
		"another user's common name":       {pkix.Name{CommonName: "system:kube-controller-manager"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			requester, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generating requester key: %v", err)
			}
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: tc.subject}, requester)
			if err != nil {
				t.Fatalf("creating CSR: %v", err)
			}
			in := bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
			var out bytes.Buffer
			err = Sign(context.Background(), config, in, &out)
			if !tc.allowed {
				if err == nil {
					t.Error("the CA signed a request for another user's name")
				}
				return
			}
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			leaf, err := pemutil.ParseCertificate(out.Bytes())
			if err != nil {
				t.Fatalf("parsing the chain: %v", err)
			}
			if leaf.Subject.CommonName != "claude" {
				t.Errorf("common name: got %q, want claude", leaf.Subject.CommonName)
			}
			if !slices.Equal(leaf.Subject.Organization, []string{"claude", "readers"}) {
				t.Errorf("organization: got %q, want [claude readers]", leaf.Subject.Organization)
			}
			if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&requester.PublicKey) {
				t.Error("the certificate isn't for the request's key")
			}
		})
	}
}

// A token without groups, which only an older k8sss would mint, gets a
// certificate in no group at all rather than system:masters.
func TestTheRealCAGrantsNoGroupWithoutTheClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
	testHome(t)
	config := realCAConfig(t, newTestCA(t), key.Public(), comment)

	signing, err := openSigningKey(config.KeyURI)
	if err != nil {
		t.Fatalf("openSigningKey: %v", err)
	}
	defer signing.Close()
	kid, err := token.GenerateKeyID(signing.OpaqueSigner)
	if err != nil {
		t.Fatalf("GenerateKeyID: %v", err)
	}
	csr := testCSR(t, config.Username)
	ott, err := cautils.NewTokenGenerator(kid, kid, config.CAURL+"/1.0/sign", "", time.Time{}, time.Time{},
		&jose.JSONWebKey{Key: signing.OpaqueSigner, Algorithm: string(signing.alg)}).
		SignToken(config.Username, nil, token.WithFingerprint(csr))
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	client, err := ca.NewClient(config.CAURL, ca.WithRootFile(config.clientCACrt))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err := client.Sign(&api.SignRequest{CsrPEM: api.CertificateRequest{CertificateRequest: csr}, OTT: ott})
	if err != nil {
		return // refusing it is as good
	}
	if org := resp.ServerPEM.Subject.Organization; len(org) != 0 {
		t.Errorf("organization: got %q, want none", org)
	}
}

// realCAConfig points a config at a freshly started real CA, with the CA's
// root where setup would have put it.
func realCAConfig(t *testing.T, testCA *testCA, authorized crypto.PublicKey, comment string) *Config {
	t.Helper()
	config, err := (&Params{
		CAURL:           startRealCA(t, testCA, authorized),
		KeyURI:          "sshagentkms:" + comment,
		Username:        "system:admin",
		Groups:          "system:masters",
		KubeAPIHostname: "nas",
	}).Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if err := os.MkdirAll(config.dir, 0o700); err != nil {
		t.Fatalf("creating config directory: %v", err)
	}
	if err := os.WriteFile(config.clientCACrt, []byte(encodeCert(testCA.cert)), 0o644); err != nil {
		t.Fatalf("writing root: %v", err)
	}
	return config
}

// credentialLeaf pulls the issued certificate out of an ExecCredential.
func credentialLeaf(t *testing.T, out []byte) *x509.Certificate {
	t.Helper()
	var credential struct {
		Status struct {
			ClientCertificateData string `json:"clientCertificateData"`
			ClientKeyData         string `json:"clientKeyData"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &credential); err != nil {
		t.Fatalf("parsing credential %s: %v", out, err)
	}
	pair, err := tls.X509KeyPair(
		[]byte(credential.Status.ClientCertificateData),
		[]byte(credential.Status.ClientKeyData),
	)
	if err != nil {
		t.Fatalf("loading the issued key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the issued certificate: %v", err)
	}
	return leaf
}
