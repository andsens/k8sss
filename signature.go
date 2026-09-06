package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// JWS wants ECDSA signatures as a raw r||s concatenation: two fixed-width
// big-endian integers, each exactly coordLen bytes (RFC 7518 section 3.4).
// KMS backends do not agree on what they hand back. A plain crypto.Signer
// returns ASN.1 DER, while the SSH agent returns SSH wire format; both carry
// length metadata and may prepend a 0x00 byte to keep an integer positive.
// jwsSignature detects which one it got and normalises to raw r||s.
func jwsSignature(alg string, sig []byte) ([]byte, error) {
	size := coordLen(alg)
	if size == 0 {
		// EdDSA and RSA signatures are already in the form JWS expects.
		return sig, nil
	}
	switch {
	case len(sig) == size*2:
		return sig, nil
	case len(sig) > 2 && sig[0] == 0x30:
		return derToRaw(sig, size)
	default:
		return sshToRaw(sig, size)
	}
}

// coordLen is the byte width of each of r and s for an ECDSA algorithm, and 0
// for everything else.
func coordLen(alg string) int {
	switch alg {
	case "ES256": // P-256
		return 32
	case "ES384": // P-384
		return 48
	case "ES512": // P-521, whose 521 bits round up to 66 bytes
		return 66
	default:
		return 0
	}
}

func derToRaw(sig []byte, size int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse DER ECDSA signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("Trailing data after DER ECDSA signature")
	}
	return concatRS(parsed.R, parsed.S, size)
}

func sshToRaw(sig []byte, size int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if err := ssh.Unmarshal(sig, &parsed); err != nil {
		return nil, fmt.Errorf("Unable to parse SSH ECDSA signature: %w", err)
	}
	return concatRS(parsed.R, parsed.S, size)
}

// concatRS left-pads r and s to the fixed width JWS requires.
func concatRS(r, s *big.Int, size int) ([]byte, error) {
	if r == nil || s == nil {
		return nil, fmt.Errorf("ECDSA signature is missing r or s")
	}
	if r.Sign() < 0 || s.Sign() < 0 {
		return nil, fmt.Errorf("ECDSA signature has a negative component")
	}
	if r.BitLen() > size*8 || s.BitLen() > size*8 {
		return nil, fmt.Errorf("ECDSA signature component is wider than the %d byte curve", size)
	}
	out := make([]byte, size*2)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out, nil
}

// hashFor is the digest a JWS algorithm signs over. EdDSA hashes internally,
// so it reports no hash, matching the crypto.Signer contract for ed25519.
func hashFor(alg string) crypto.Hash {
	switch alg {
	case "ES256", "RS256", "PS256":
		return crypto.SHA256
	case "ES384", "RS384", "PS384":
		return crypto.SHA384
	case "ES512", "RS512", "PS512":
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}

// verifySignature checks a normalised JWS signature against the public key
// before it is sent to the CA. The KMS backends disagree enough about
// signature encoding that catching a mismatch here turns a puzzling
// "unauthorized" from the CA into a precise local error.
func verifySignature(pub crypto.PublicKey, alg string, signingInput, sig []byte) error {
	hash := hashFor(alg)
	var digest []byte
	if hash != crypto.Hash(0) {
		h := hash.New()
		h.Write(signingInput)
		digest = h.Sum(nil)
	}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		size := coordLen(alg)
		if len(sig) != size*2 {
			return fmt.Errorf("ECDSA signature is %d bytes, expected %d", len(sig), size*2)
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(key, digest, r, s) {
			return fmt.Errorf("ECDSA signature does not verify against the public key")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(key, signingInput, sig) {
			return fmt.Errorf("Ed25519 signature does not verify against the public key")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, hash, digest, sig); err != nil {
			return fmt.Errorf("RSA signature does not verify against the public key: %w", err)
		}
	default:
		return fmt.Errorf("Unsupported public key type %T", pub)
	}
	return nil
}
