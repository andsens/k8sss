package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPastHalfLife(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	now := time.Now()
	// The deployment issues 30 minute certificates and expects a renewal
	// after 15, which is what --expires-in 50% meant.
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

	missing := filepath.Join(dir, "missing.crt")
	if renew, err := needsRenewal(missing); err != nil || !renew {
		t.Errorf("missing certificate: got (%v, %v), want (true, nil)", renew, err)
	}

	// A truncated or corrupt file should repair itself rather than fail.
	corrupt := filepath.Join(dir, "corrupt.crt")
	if err := os.WriteFile(corrupt, []byte("-----BEGIN CERTIFICATE-----\nnonsense\n"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if renew, err := needsRenewal(corrupt); err != nil || !renew {
		t.Errorf("corrupt certificate: got (%v, %v), want (true, nil)", renew, err)
	}

	fresh := filepath.Join(dir, "fresh.crt")
	cert := ca.issue(t, "system:admin", time.Now(), time.Now().Add(30*time.Minute), &key.PublicKey)
	if err := os.WriteFile(fresh, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if renew, err := needsRenewal(fresh); err != nil || renew {
		t.Errorf("fresh certificate: got (%v, %v), want (false, nil)", renew, err)
	}
}
