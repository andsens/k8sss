package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ssh/agent"
)

// These tests drive the whole cert flow against a stand-in CA, with the
// authentication key held by a real SSH agent. That path is the one worth
// exercising end to end: the agent returns ECDSA signatures in SSH wire
// format, which is neither what JWS wants nor what a plain crypto.Signer
// would have produced.
func TestIssueCertAgainstAStandInCA(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  func(*testing.T) crypto.Signer
	}{
		{"ecdsa", func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			return key
		}},
		{"ed25519", func(t *testing.T) crypto.Signer {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			return key
		}},
		// An SSH agent signs RSA with the legacy SHA-1 algorithm unless asked
		// otherwise, which would not back the RS256 the token header declares.
		{"rsa", func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			return key
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authKey := tc.key(t)
			const comment = "tester@workstation"
			t.Setenv("SSH_AUTH_SOCK", startAgent(t, authKey, comment))

			ca := newTestCA(t)
			caURL := startCA(t, ca, authKey.Public())

			dir := t.TempDir()
			pth := paths{
				dir:         dir,
				clientCACrt: filepath.Join(dir, "client-ca.crt"),
				userCrt:     filepath.Join(dir, "system:admin.crt"),
				userKey:     filepath.Join(dir, "system:admin.key"),
			}
			if err := os.WriteFile(pth.clientCACrt, []byte(encodeCert(ca.cert)), 0o644); err != nil {
				t.Fatalf("writing root: %v", err)
			}
			p := params{
				Cert:     true,
				CAURL:    caURL,
				KeyURI:   "sshagentkms:" + comment,
				Username: "system:admin",
			}

			out := captureStdout(t, func() {
				if err := issueCert(&p, &pth); err != nil {
					t.Fatalf("issueCert: %v", err)
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
			// The pair has to be loadable as a TLS client certificate, which
			// is all kubectl ultimately does with it.
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
				t.Errorf("common name: got %q, want %q", leaf.Subject.CommonName, "system:admin")
			}

			// A second call must reuse the certificate rather than mint a new
			// one, since it is nowhere near its half life yet.
			before, err := os.ReadFile(pth.userCrt)
			if err != nil {
				t.Fatalf("reading certificate: %v", err)
			}
			captureStdout(t, func() {
				if err := issueCert(&p, &pth); err != nil {
					t.Fatalf("second issueCert: %v", err)
				}
			})
			after, err := os.ReadFile(pth.userCrt)
			if err != nil {
				t.Fatalf("reading certificate: %v", err)
			}
			if string(before) != string(after) {
				t.Error("a still-valid certificate was replaced")
			}
		})
	}
}

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

// startCA runs a stand-in for step-ca that checks the one-time token the way
// the real one does before issuing a certificate.
func startCA(t *testing.T, ca *testCA, authorized crypto.PublicKey) string {
	t.Helper()
	kid, err := jose.Thumbprint(&jose.JSONWebKey{Key: authorized})
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/roots.pem", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, encodeCert(ca.cert))
	})
	mux.HandleFunc("/1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		var request signRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, `{"message":"malformed request"}`, http.StatusBadRequest)
			return
		}
		// go-jose parses and verifies the token independently of the code
		// that produced it, so a malformed JWS fails here.
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
		var claims tokenPayload
		if err := json.Unmarshal(payload, &claims); err != nil {
			http.Error(w, `{"message":"malformed claims"}`, http.StatusUnauthorized)
			return
		}
		block, _ := pem.Decode([]byte(request.CSR))
		if block == nil {
			http.Error(w, `{"message":"malformed csr"}`, http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, `{"message":"invalid csr"}`, http.StatusBadRequest)
			return
		}
		if csr.Subject.CommonName != claims.Sub {
			http.Error(w, `{"message":"common name does not match the token"}`, http.StatusForbidden)
			return
		}
		leaf := ca.issue(t, csr.Subject.CommonName, time.Now(), time.Now().Add(30*time.Minute), csr.PublicKey)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(signResponse{
			Crt:       encodeCert(leaf),
			CA:        encodeCert(ca.cert),
			CertChain: []string{encodeCert(leaf), encodeCert(ca.cert)},
		})
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// serverCert issues the TLS certificate the stand-in CA serves on, mirroring
// step-ca signing its own serving certificate with the Kubernetes client CA.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issuing server certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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

// Guard against the SSH signer being handed a digest, which the agent would
// hash a second time and produce a signature nobody can verify.
func TestSSHAgentSignerReceivesTheMessage(t *testing.T) {
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

	if !signing.hashesMessage {
		t.Error("the SSH agent signer was not recognised as hashing the message itself")
	}
	if signing.alg != "ES256" {
		t.Errorf("algorithm: got %q, want ES256", signing.alg)
	}
	token, err := signing.token("https://ca.example.com:9000", "system:admin")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	jws, err := jose.ParseJWS(token)
	if err != nil {
		t.Fatalf("the token is not a valid JWS: %v", err)
	}
	if _, err := jws.Verify(key.Public()); err != nil {
		t.Errorf("the token does not verify: %v", err)
	}
}
