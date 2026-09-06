package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
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
		Subject:               pkix.Name{CommonName: "kube-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
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

// issue signs a leaf certificate valid for the given window.
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

func TestClientChainDropsTheRoot(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	leaf := ca.issue(t, "system:admin", time.Now(), time.Now().Add(30*time.Minute), &key.PublicKey)

	chain, err := clientChain(&signResponse{
		Crt:       encodeCert(leaf),
		CA:        encodeCert(ca.cert),
		CertChain: []string{encodeCert(leaf), encodeCert(ca.cert)},
	})
	if err != nil {
		t.Fatalf("clientChain: %v", err)
	}
	if got := strings.Count(string(chain), "BEGIN CERTIFICATE"); got != 1 {
		t.Errorf("got %d certificates, want just the leaf", got)
	}
	block, _ := pem.Decode(chain)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if parsed.Subject.CommonName != "system:admin" {
		t.Errorf("got %q, want the leaf", parsed.Subject.CommonName)
	}
}

func TestClientChainFallsBackToTheLeaf(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	leaf := ca.issue(t, "system:admin", time.Now(), time.Now().Add(30*time.Minute), &key.PublicKey)

	chain, err := clientChain(&signResponse{Crt: encodeCert(leaf)})
	if err != nil {
		t.Fatalf("clientChain: %v", err)
	}
	if got := strings.Count(string(chain), "BEGIN CERTIFICATE"); got != 1 {
		t.Errorf("got %d certificates, want 1", got)
	}
}

// A self-signed leaf is unusual but must not be filtered away as a root.
func TestClientChainKeepsASelfSignedLeaf(t *testing.T) {
	ca := newTestCA(t)
	if _, err := clientChain(&signResponse{CertChain: []string{encodeCert(ca.cert)}}); err != nil {
		t.Fatalf("clientChain: %v", err)
	}
}

func TestClientChainRejectsGarbage(t *testing.T) {
	if _, err := clientChain(&signResponse{Crt: "not a certificate"}); err == nil {
		t.Error("expected an error for a non-PEM response")
	}
}
