package k8sss

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/sshagentkms"
	"golang.org/x/crypto/ssh"

	// Every KMS backend registers itself on import and ships a stub for
	// platforms or build configurations it cannot support, so importing them
	// all keeps the set of usable key URIs as wide as the build allows.
	_ "go.step.sm/crypto/kms/mackms"
	_ "go.step.sm/crypto/kms/pkcs11"
	_ "go.step.sm/crypto/kms/tpmkms"
	_ "go.step.sm/crypto/kms/yubikey"
)

// signingKey is the authentication key named by --keyuri, presented as the
// jose.OpaqueSigner that the token package signs with.
type signingKey struct {
	jose.OpaqueSigner
	manager apiv1.KeyManager
	alg     jose.SignatureAlgorithm
}

func openSigningKey(keyURI string) (_ *signingKey, err error) {
	manager, err := kms.New(context.Background(), apiv1.Options{URI: keyURI})
	if err != nil {
		return nil, fmt.Errorf("Unable to open the KMS for '%s': %w", keyURI, err)
	}
	// The caller only gets something to Close when this succeeds.
	defer func() {
		if err != nil {
			manager.Close()
		}
	}()
	key := &signingKey{manager: manager}
	public, err := manager.GetPublicKey(&apiv1.GetPublicKeyRequest{Name: keyURI})
	if err != nil {
		return nil, fmt.Errorf("Unable to read the public key for '%s': %w", keyURI, err)
	}
	if key.alg, err = algorithmFor(public); err != nil {
		return nil, err
	}
	signer, err := manager.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: keyURI})
	if err != nil {
		return nil, fmt.Errorf("Unable to create a signer for '%s': %w", keyURI, err)
	}
	if wrapped, ok := signer.(*sshagentkms.WrappedSSHSigner); ok {
		agent, ok := wrapped.Signer.(ssh.AlgorithmSigner)
		if !ok {
			err = fmt.Errorf("The SSH agent holding '%s' cannot be asked for a signature algorithm", keyURI)
			return nil, err
		}
		key.OpaqueSigner = &sshAgentSigner{
			signer: agent,
			public: &jose.JSONWebKey{Key: public, Algorithm: string(key.alg), Use: "sig"},
			alg:    key.alg,
		}
	} else {
		key.OpaqueSigner = jose.NewOpaqueSigner(signer)
	}
	return key, nil
}

func (k *signingKey) Close() error { return k.manager.Close() }

// token mints the one-time token that authorises a single signing request.
func (k *signingKey) token(caURL, username string) (string, error) {
	// The JWK provisioner is named after the thumbprint of its key, so the
	// issuer has to be that same thumbprint for the CA to find it.
	kid, err := token.GenerateKeyID(k.OpaqueSigner)
	if err != nil {
		return "", fmt.Errorf("Unable to compute the key ID: %w", err)
	}
	jti := make([]byte, 32)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("Unable to generate a token ID: %w", err)
	}
	ott, err := provision.New(username,
		token.WithIssuer(kid),
		token.WithAudience(caURL+"/1.0/sign"),
		token.WithSANS([]string{username}),
		token.WithJWTID(hex.EncodeToString(jti)),
	)
	if err != nil {
		return "", fmt.Errorf("Unable to build the token: %w", err)
	}
	signed, err := ott.SignedString(string(k.alg), k.OpaqueSigner)
	if err != nil {
		return "", fmt.Errorf("Unable to sign the token: %w", err)
	}
	return signed, nil
}

// algorithmFor picks the JWS algorithm for a key the same way
// `step crypto jwk create --use sig` does, so the thumbprint and the token
// header match what the CA was configured with.
func algorithmFor(public crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", fmt.Errorf("Unsupported ECDSA curve '%s'", key.Curve.Params().Name)
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	case *rsa.PublicKey:
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("Unsupported key type %T", public)
	}
}

// sshAgentSigner signs JWS payloads with a key held by an SSH agent.
//
// go-jose's own crypto.Signer wrapper cannot be used for this: for ECDSA it
// hands the signer a digest and parses the result as ASN.1 DER, whereas an SSH
// agent hashes the message itself and answers in SSH wire format. The agent
// also has to be asked for rsa-sha2-256 by name, since it otherwise signs with
// the legacy SHA-1 ssh-rsa algorithm, which cannot back an RS256 token.
type sshAgentSigner struct {
	signer ssh.AlgorithmSigner
	public *jose.JSONWebKey
	alg    jose.SignatureAlgorithm
}

func (s *sshAgentSigner) Public() *jose.JSONWebKey { return s.public }

func (s *sshAgentSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{s.alg}
}

func (s *sshAgentSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != s.alg {
		return nil, fmt.Errorf("this key signs %s, not %s", s.alg, alg)
	}
	var sshAlg string
	if s.alg == jose.RS256 {
		sshAlg = ssh.KeyAlgoRSASHA256
	}
	signature, err := s.signer.SignWithAlgorithm(rand.Reader, payload, sshAlg)
	if err != nil {
		return nil, err
	}
	if size := coordLen(s.alg); size > 0 {
		return sshECDSAToJWS(signature.Blob, size)
	}
	return signature.Blob, nil
}

// coordLen is the byte width of each of r and s for an ECDSA algorithm, and 0
// for everything else.
func coordLen(alg jose.SignatureAlgorithm) int {
	switch alg {
	case jose.ES256: // P-256
		return 32
	case jose.ES384: // P-384
		return 48
	case jose.ES512: // P-521, whose 521 bits round up to 66 bytes
		return 66
	default:
		return 0
	}
}

// sshECDSAToJWS converts the two mpints of an SSH ECDSA signature into the
// fixed-width r||s concatenation JWS expects (RFC 7518 section 3.4).
func sshECDSAToJWS(blob []byte, size int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if err := ssh.Unmarshal(blob, &parsed); err != nil {
		return nil, fmt.Errorf("unable to parse the SSH ECDSA signature: %w", err)
	}
	if parsed.R.BitLen() > size*8 || parsed.S.BitLen() > size*8 {
		return nil, fmt.Errorf("ECDSA signature component is wider than the %d byte curve", size)
	}
	out := make([]byte, size*2)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])
	return out, nil
}
