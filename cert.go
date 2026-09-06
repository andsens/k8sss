package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.step.sm/crypto/x509util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauth "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

const (
	renewAttempts = 3
	renewBackoff  = 5 * time.Second
)

// issueCert implements the kubectl credential plugin: it prints a client
// certificate, renewing it first when the stored one is past its half life.
func issueCert(p *params, pth *paths) error {
	renew, err := needsRenewal(pth.userCrt)
	if err != nil {
		return err
	}
	if renew {
		slog.Debug("Renewing client certificate")
		if err := renewCert(p, pth); err != nil {
			return err
		}
	}
	cert, err := os.ReadFile(pth.userCrt)
	if err != nil {
		return fmt.Errorf("Unable to read %s: %w", pth.userCrt, err)
	}
	key, err := os.ReadFile(pth.userKey)
	if err != nil {
		return fmt.Errorf("Unable to read %s: %w", pth.userKey, err)
	}
	credential := &clientauth.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &clientauth.ExecCredentialStatus{
			ClientCertificateData: string(cert),
			ClientKeyData:         string(key),
		},
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(credential); err != nil {
		return fmt.Errorf("Unable to write the credential: %w", err)
	}
	return nil
}

// needsRenewal reports whether a new certificate should be requested. A
// certificate that cannot be read is treated as due for renewal rather than
// as an error, so a truncated or corrupt file repairs itself.
func needsRenewal(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("Unable to read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, nil
	}
	return pastHalfLife(cert, time.Now()), nil
}

// pastHalfLife matches `step certificate needs-renewal --expires-in 50%`:
// renew once more of the certificate's lifetime is behind it than ahead.
func pastHalfLife(cert *x509.Certificate, now time.Time) bool {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return now.After(cert.NotAfter.Add(-lifetime / 2))
}

func renewCert(p *params, pth *paths) error {
	root, err := os.ReadFile(pth.clientCACrt)
	if err != nil {
		return fmt.Errorf("Unable to read %s, has `k8sss setup` been run for this cluster?: %w", pth.clientCACrt, err)
	}
	key, err := openSigningKey(p.KeyURI)
	if err != nil {
		return err
	}
	defer key.Close()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Unable to generate a client key: %w", err)
	}
	csr, err := x509util.CreateCertificateRequest(p.Username, []string{p.Username}, private)
	if err != nil {
		return fmt.Errorf("Unable to create a certificate request: %w", err)
	}

	var chain []byte
	for remaining := renewAttempts - 1; ; remaining-- {
		// The CA remembers every token it has seen, so each attempt needs a
		// freshly minted one.
		token, err := key.token(p.CAURL, p.Username)
		if err != nil {
			return err
		}
		if chain, err = signCertificate(p.CAURL, root, csr, token); err == nil {
			break
		}
		if remaining <= 0 {
			return fmt.Errorf("Failed to issue kube-api certificate (aborting):\n%w", err)
		}
		slog.Error(fmt.Sprintf("Failed to issue kube-api certificate (%d tries remaining):\n%s", remaining, err))
		time.Sleep(renewBackoff)
	}

	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("Unable to encode the client key: %w", err)
	}
	if err := os.MkdirAll(pth.dir, 0o700); err != nil {
		return fmt.Errorf("Unable to create %s: %w", pth.dir, err)
	}
	if err := os.WriteFile(pth.userKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return fmt.Errorf("Unable to write %s: %w", pth.userKey, err)
	}
	// Written last: a certificate on disk is taken to mean its key is there too.
	if err := os.WriteFile(pth.userCrt, chain, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", pth.userCrt, err)
	}
	return nil
}
