package k8sss

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/certificates/api"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"
)

// testCA issues certificates for the tests, standing in for step-ca.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kube-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) issue(t *testing.T, commonName string, notBefore, notAfter time.Time, public any) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"system:masters"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		t.Fatalf("issuing certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

func encodeCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// standInCA runs a stand-in for step-ca that checks the one-time token the way
// the real one does before issuing a certificate. It answers on both the
// versioned and unversioned sign paths, as step-ca mounts its API at each.
type standInCA struct {
	url        string
	mu         sync.Mutex
	signedPath string
	tokens     []string
}

func startCA(t *testing.T, ca *testCA, authorized crypto.PublicKey) *standInCA {
	t.Helper()
	stand := &standInCA{}
	kid, err := jose.Thumbprint(&jose.JSONWebKey{Key: authorized})
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}

	sign := func(w http.ResponseWriter, r *http.Request) {
		var request api.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, `{"message":"malformed request"}`, http.StatusBadRequest)
			return
		}
		// go-jose parses and verifies the token independently of the code that
		// produced it, so a malformed JWS fails here.
		jws, err := jose.ParseJWS(request.OTT)
		if err != nil {
			http.Error(w, `{"message":"malformed token"}`, http.StatusUnauthorized)
			return
		}
		if got := jws.Signatures[0].Header.KeyID; got != kid {
			http.Error(w, `{"message":"unknown provisioner"}`, http.StatusUnauthorized)
			return
		}
		payload, err := jws.Verify(authorized)
		if err != nil {
			http.Error(w, `{"message":"invalid signature"}`, http.StatusUnauthorized)
			return
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
			http.Error(w, `{"message":"malformed claims"}`, http.StatusUnauthorized)
			return
		}
		if claims.Issuer != kid {
			http.Error(w, `{"message":"issuer is not the provisioner"}`, http.StatusUnauthorized)
			return
		}
		stand.mu.Lock()
		stand.signedPath = r.URL.Path
		replayed := false
		for _, seen := range stand.tokens {
			if seen == claims.ID {
				replayed = true
			}
		}
		stand.tokens = append(stand.tokens, claims.ID)
		stand.mu.Unlock()
		if replayed {
			http.Error(w, `{"message":"token already used"}`, http.StatusUnauthorized)
			return
		}
		if request.CsrPEM.CertificateRequest == nil || request.CsrPEM.CheckSignature() != nil {
			http.Error(w, `{"message":"invalid csr"}`, http.StatusBadRequest)
			return
		}
		// step-ca's JWK provisioner signs only the CSR the token names.
		sum := sha256.Sum256(request.CsrPEM.Raw)
		if claims.CNF.Fingerprint != base64.RawURLEncoding.EncodeToString(sum[:]) {
			http.Error(w, `{"message":"csr does not match the token fingerprint"}`, http.StatusForbidden)
			return
		}
		if request.CsrPEM.Subject.CommonName != claims.Subject {
			http.Error(w, `{"message":"common name does not match the token"}`, http.StatusForbidden)
			return
		}
		// step-ca checks the CSR's names against the token's sans claim after
		// running both through the same classifier. A name like
		// "system:admin" parses as a URI rather than a DNS name, so the CSR
		// has to be built the same way the CA reads the claim.
		dnsNames, ips, emails, uris := x509util.SplitSANs(claims.SANS)
		if !slices.Equal(request.CsrPEM.DNSNames, dnsNames) ||
			!slices.Equal(request.CsrPEM.EmailAddresses, emails) ||
			len(request.CsrPEM.IPAddresses) != len(ips) ||
			len(request.CsrPEM.URIs) != len(uris) {
			http.Error(w, `{"message":"csr names do not match the token sans"}`, http.StatusForbidden)
			return
		}
		for i, uri := range uris {
			if request.CsrPEM.URIs[i].String() != uri.String() {
				http.Error(w, `{"message":"csr uri does not match the token sans"}`, http.StatusForbidden)
				return
			}
		}
		leaf := ca.issue(t, request.CsrPEM.Subject.CommonName, time.Now(), time.Now().Add(30*time.Minute), request.CsrPEM.PublicKey)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(&api.SignResponse{
			ServerPEM:    api.Certificate{Certificate: leaf},
			CaPEM:        api.Certificate{Certificate: ca.cert},
			CertChainPEM: []api.Certificate{{Certificate: leaf}, {Certificate: ca.cert}},
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/roots.pem", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, encodeCert(ca.cert))
	})
	mux.HandleFunc("/sign", sign)
	mux.HandleFunc("/1.0/sign", sign)

	server := httptest.NewUnstartedServer(mux)
	// step-ca signs its own serving certificate with the same root it issues
	// from, which for k8sss is the Kubernetes client CA.
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{ca.cert.Raw},
		PrivateKey:  ca.key,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	stand.url = server.URL
	return stand
}

func TestCertAgainstAStandInCA(t *testing.T) {
	for name, key := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			const comment = "tester@workstation"
			t.Setenv("SSH_AUTH_SOCK", startAgent(t, key, comment))
			testHome(t)

			ca := newTestCA(t)
			stand := startCA(t, ca, key.Public())
			p := &Params{
				CAURL:           stand.url,
				KeyURI:          "sshagentkms:" + comment,
				Username:        "system:admin",
				KubeAPIHostname: "nas",
			}
			c, err := p.Config()
			if err != nil {
				t.Fatalf("Config: %v", err)
			}
			if err := os.MkdirAll(c.dir, 0o700); err != nil {
				t.Fatalf("creating config directory: %v", err)
			}
			if err := os.WriteFile(c.clientCACrt, []byte(encodeCert(ca.cert)), 0o644); err != nil {
				t.Fatalf("writing root: %v", err)
			}

			out := captureStdout(t, func() {
				if err := Cert(context.Background(), c); err != nil {
					t.Fatalf("Cert: %v", err)
				}
			})

			var credential struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Status     struct {
					ClientCertificateData string `json:"clientCertificateData"`
					ClientKeyData         string `json:"clientKeyData"`
				} `json:"status"`
			}
			if err := json.Unmarshal(out, &credential); err != nil {
				t.Fatalf("parsing credential %s: %v", out, err)
			}
			if credential.Kind != "ExecCredential" ||
				credential.APIVersion != "client.authentication.k8s.io/v1beta1" {
				t.Errorf("unexpected credential envelope: %+v", credential)
			}
			// The pair has to load as a TLS client certificate, which is all
			// kubectl ultimately does with it.
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
			if leaf.Subject.CommonName != "system:admin" {
				t.Errorf("common name: got %q", leaf.Subject.CommonName)
			}

			// A second call reuses the certificate rather than minting one,
			// since it is nowhere near its half life.
			before, err := os.ReadFile(c.userCrt)
			if err != nil {
				t.Fatalf("reading certificate: %v", err)
			}
			captureStdout(t, func() {
				if err := Cert(context.Background(), c); err != nil {
					t.Fatalf("second Cert: %v", err)
				}
			})
			after, err := os.ReadFile(c.userCrt)
			if err != nil {
				t.Fatalf("reading certificate: %v", err)
			}
			if string(before) != string(after) {
				t.Error("a still-valid certificate was replaced")
			}
			// step-ca mounts its API at the root and again under /1.0; the
			// client uses the unversioned path while the token audience names
			// the versioned one, and matchesAudience accepts both.
			if stand.signedPath != "/sign" {
				t.Errorf("the client signed against %q, want /sign", stand.signedPath)
			}
		})
	}
}

// The certificate file holds what `step ca certificate` would have written:
// the whole chain the CA returned.
func TestCertChainKeepsTheWholeChain(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	leaf := ca.issue(t, "system:admin", time.Now(), time.Now().Add(30*time.Minute), &key.PublicKey)

	chain, err := certChain(&api.SignResponse{
		ServerPEM:    api.Certificate{Certificate: leaf},
		CaPEM:        api.Certificate{Certificate: ca.cert},
		CertChainPEM: []api.Certificate{{Certificate: leaf}, {Certificate: ca.cert}},
	})
	if err != nil {
		t.Fatalf("certChain: %v", err)
	}
	if got := strings.Count(string(chain), "BEGIN CERTIFICATE"); got != 2 {
		t.Errorf("got %d certificates, want the leaf and the CA", got)
	}
	block, _ := pem.Decode(chain)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if parsed.Subject.CommonName != "system:admin" {
		t.Errorf("the leaf should come first, got %q", parsed.Subject.CommonName)
	}
}

// An older CA answers with crt and ca instead of a chain.
func TestCertChainFallsBackToTheLeafAndCA(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	leaf := ca.issue(t, "system:admin", time.Now(), time.Now().Add(30*time.Minute), &key.PublicKey)
	chain, err := certChain(&api.SignResponse{
		ServerPEM: api.Certificate{Certificate: leaf},
		CaPEM:     api.Certificate{Certificate: ca.cert},
	})
	if err != nil {
		t.Fatalf("certChain: %v", err)
	}
	if got := strings.Count(string(chain), "BEGIN CERTIFICATE"); got != 2 {
		t.Errorf("got %d certificates, want 2", got)
	}
}

func TestCertChainRejectsAnEmptyResponse(t *testing.T) {
	if _, err := certChain(&api.SignResponse{}); err == nil {
		t.Error("expected an error for an empty response")
	}
}

func TestPastHalfLife(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	now := time.Now()
	// The deployment issues 30 minute certificates and expects a renewal after
	// 15, which is what --expires-in 50% meant.
	for _, tc := range []struct {
		name  string
		age   time.Duration
		renew bool
	}{
		{"freshly issued", 0, false},
		{"just before half life", 14 * time.Minute, false},
		{"just after half life", 16 * time.Minute, true},
		{"expired", 31 * time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued := now.Add(-tc.age)
			cert := ca.issue(t, "system:admin", issued, issued.Add(30*time.Minute), &key.PublicKey)
			if got := pastHalfLife(cert, now); got != tc.renew {
				t.Errorf("got %v, want %v", got, tc.renew)
			}
		})
	}
}

func TestNeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	if renew, err := needsRenewal(filepath.Join(dir, "missing.crt")); err != nil || !renew {
		t.Errorf("missing certificate: got (%v, %v), want (true, nil)", renew, err)
	}

	// A truncated or corrupt file should repair itself rather than fail.
	corrupt := filepath.Join(dir, "corrupt.crt")
	if err := os.WriteFile(corrupt, []byte("-----BEGIN CERTIFICATE-----\nnonsense\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if renew, err := needsRenewal(corrupt); err != nil || !renew {
		t.Errorf("corrupt certificate: got (%v, %v), want (true, nil)", renew, err)
	}

	fresh := filepath.Join(dir, "fresh.crt")
	cert := ca.issue(t, "system:admin", time.Now(), time.Now().Add(30*time.Minute), &key.PublicKey)
	if err := os.WriteFile(fresh, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if renew, err := needsRenewal(fresh); err != nil || renew {
		t.Errorf("fresh certificate: got (%v, %v), want (false, nil)", renew, err)
	}
}

func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = write
	done := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(read)
		done <- out
	}()
	fn()
	os.Stdout = original
	write.Close()
	return <-done
}
