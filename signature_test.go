package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh"
)

// asn1Sig and sshSig re-encode a signature the way the two KMS families do,
// so the tests exercise jwsSignature with the input it sees in the wild.
func asn1Sig(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshalling DER: %v", err)
	}
	return der
}

func sshSig(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	return ssh.Marshal(struct{ R, S *big.Int }{r, s})
}

func TestJWSSignatureNormalisesEveryEncoding(t *testing.T) {
	// A leading bit set in r forces both DER and SSH wire format to prepend a
	// 0x00 byte, and a tiny s needs padding out to the full coordinate width.
	r := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 32))
	s := big.NewInt(1)
	want := make([]byte, 64)
	r.FillBytes(want[:32])
	s.FillBytes(want[32:])

	for name, sig := range map[string][]byte{
		"DER":      asn1Sig(t, r, s),
		"SSH wire": sshSig(t, r, s),
		"raw":      want,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := jwsSignature("ES256", sig)
			if err != nil {
				t.Fatalf("jwsSignature: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}
}

func TestJWSSignatureRoundTripsRealSignatures(t *testing.T) {
	for _, tc := range []struct {
		alg   string
		curve elliptic.Curve
		size  int
	}{
		{"ES256", elliptic.P256(), 32},
		{"ES384", elliptic.P384(), 48},
		{"ES512", elliptic.P521(), 66},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			input := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06YWRtaW4ifQ")
			hash := hashFor(tc.alg).New()
			hash.Write(input)
			r, s, err := ecdsa.Sign(rand.Reader, key, hash.Sum(nil))
			if err != nil {
				t.Fatalf("signing: %v", err)
			}
			for name, sig := range map[string][]byte{
				"DER":      asn1Sig(t, r, s),
				"SSH wire": sshSig(t, r, s),
			} {
				got, err := jwsSignature(tc.alg, sig)
				if err != nil {
					t.Fatalf("%s: jwsSignature: %v", name, err)
				}
				if len(got) != tc.size*2 {
					t.Errorf("%s: got %d bytes, want %d", name, len(got), tc.size*2)
				}
				if err := verifySignature(&key.PublicKey, tc.alg, input, got); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
		})
	}
}

// EdDSA and RSA signatures already arrive in the shape JWS wants.
func TestJWSSignatureLeavesNonECDSAAlone(t *testing.T) {
	sig := bytes.Repeat([]byte{0x30}, 64)
	got, err := jwsSignature("EdDSA", sig)
	if err != nil {
		t.Fatalf("jwsSignature: %v", err)
	}
	if !bytes.Equal(got, sig) {
		t.Errorf("got %x, want %x", got, sig)
	}
}

func TestJWSSignatureRejectsOversizedComponents(t *testing.T) {
	tooBig := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 33))
	if _, err := jwsSignature("ES256", asn1Sig(t, tooBig, big.NewInt(1))); err == nil {
		t.Error("expected an error for a component wider than the curve")
	}
}

func TestVerifySignatureCatchesATamperedSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	input := []byte("header.payload")
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig, err := jwsSignature("ES256", asn1Sig(t, r, s))
	if err != nil {
		t.Fatalf("jwsSignature: %v", err)
	}
	sig[0] ^= 0xff
	if err := verifySignature(&key.PublicKey, "ES256", input, sig); err == nil {
		t.Error("expected a tampered signature to fail verification")
	}
}

func TestVerifySignatureAcceptsEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	input := []byte("header.payload")
	if err := verifySignature(public, "EdDSA", input, ed25519.Sign(private, input)); err != nil {
		t.Errorf("verifySignature: %v", err)
	}
}
