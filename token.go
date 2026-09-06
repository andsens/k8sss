package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/sshagentkms"

	// Every backend registers itself on import and ships a stub for platforms
	// or build configurations it cannot support, so importing them all keeps
	// the set of usable key URIs as wide as the build allows.
	_ "go.step.sm/crypto/kms/mackms"
	_ "go.step.sm/crypto/kms/pkcs11"
	_ "go.step.sm/crypto/kms/tpmkms"
	_ "go.step.sm/crypto/kms/yubikey"
)

// signingKey is the authentication key named by --keyuri, along with the JWK
// metadata the CA uses to match it to a provisioner.
type signingKey struct {
	manager apiv1.KeyManager
	signer  crypto.Signer
	public  crypto.PublicKey
	alg     string
	kid     string
	// The SSH agent hashes the message itself, where a plain crypto.Signer
	// expects a digest. Which one we have decides what we hand to Sign.
	hashesMessage bool
}

func openSigningKey(keyURI string) (*signingKey, error) {
	manager, err := kms.New(context.Background(), apiv1.Options{URI: keyURI})
	if err != nil {
		return nil, fmt.Errorf("Unable to open the KMS for '%s': %w", keyURI, err)
	}
	public, err := manager.GetPublicKey(&apiv1.GetPublicKeyRequest{Name: keyURI})
	if err != nil {
		manager.Close()
		return nil, fmt.Errorf("Unable to read the public key for '%s': %w", keyURI, err)
	}
	signer, err := manager.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: keyURI})
	if err != nil {
		manager.Close()
		return nil, fmt.Errorf("Unable to create a signer for '%s': %w", keyURI, err)
	}
	alg, err := algorithmFor(public)
	if err != nil {
		manager.Close()
		return nil, err
	}
	_, hashesMessage := signer.(*sshagentkms.WrappedSSHSigner)
	key := &signingKey{
		manager:       manager,
		signer:        signer,
		public:        public,
		alg:           alg,
		hashesMessage: hashesMessage,
	}
	if key.kid, err = jose.Thumbprint(&jose.JSONWebKey{
		Key:       public,
		Use:       "sig",
		Algorithm: alg,
	}); err != nil {
		manager.Close()
		return nil, fmt.Errorf("Unable to compute the JWK thumbprint: %w", err)
	}
	slog.Debug(fmt.Sprintf("Authenticating with %s key %s", alg, key.kid))
	return key, nil
}

func (k *signingKey) Close() error { return k.manager.Close() }

// algorithmFor picks the JWS algorithm for a key the same way
// `step crypto jwk create --use sig` does, so the thumbprint and the token
// header match what the CA was configured with.
func algorithmFor(public crypto.PublicKey) (string, error) {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		case elliptic.P521():
			return "ES512", nil
		}
		return "", fmt.Errorf("Unsupported ECDSA curve '%s'", key.Curve.Params().Name)
	case ed25519.PublicKey:
		return "EdDSA", nil
	case *rsa.PublicKey:
		return "RS256", nil
	default:
		return "", fmt.Errorf("Unsupported key type %T", public)
	}
}

type tokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type tokenPayload struct {
	Aud  string   `json:"aud"`
	Exp  int64    `json:"exp"`
	Iat  int64    `json:"iat"`
	Iss  string   `json:"iss"`
	Jti  string   `json:"jti"`
	Nbf  int64    `json:"nbf"`
	Sans []string `json:"sans"`
	Sub  string   `json:"sub"`
}

// token mints the one-time token that authorises a single signing request.
// The CA rejects a repeated jti, so every attempt needs a fresh one.
func (k *signingKey) token(caURL, username string) (string, error) {
	jti := make([]byte, 32)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("Unable to generate a token ID: %w", err)
	}
	now := time.Now().Unix()
	header, err := json.Marshal(tokenHeader{Alg: k.alg, Kid: k.kid, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("Unable to encode the token header: %w", err)
	}
	payload, err := json.Marshal(tokenPayload{
		Aud:  caURL + "/1.0/sign",
		Exp:  now + 1000,
		Iat:  now,
		Iss:  k.kid,
		Jti:  hex.EncodeToString(jti),
		Nbf:  now - 1000,
		Sans: []string{username},
		Sub:  username,
	})
	if err != nil {
		return "", fmt.Errorf("Unable to encode the token payload: %w", err)
	}
	slog.Debug(fmt.Sprintf("Token header: %s", header))
	slog.Debug(fmt.Sprintf("Token payload: %s", payload))

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	signature, err := k.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

// sign produces a JWS signature over the signing input, normalising whatever
// encoding the KMS returned and checking the result against the public key
// before it leaves the machine.
func (k *signingKey) sign(signingInput []byte) ([]byte, error) {
	hash := hashFor(k.alg)
	data := signingInput
	if !k.hashesMessage && hash != crypto.Hash(0) {
		digest := hash.New()
		digest.Write(signingInput)
		data = digest.Sum(nil)
	}
	raw, err := k.signer.Sign(rand.Reader, data, hash)
	if err != nil {
		return nil, fmt.Errorf("Unable to sign the token: %w", err)
	}
	signature, err := jwsSignature(k.alg, raw)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(k.public, k.alg, signingInput, signature); err != nil {
		return nil, fmt.Errorf("The KMS produced a signature k8sss cannot use: %w", err)
	}
	return signature, nil
}
