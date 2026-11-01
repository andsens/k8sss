package k8sss

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauth "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

const (
	renewAttempts = 3
	renewBackoff  = 5 * time.Second
)

// Cert implements the kubectl credential plugin: it prints a client
// certificate, renewing it first when the stored one is past its half life.
func Cert(ctx context.Context, c *Config) error {
	renew, err := needsRenewal(c.userCrt)
	if err != nil {
		return err
	}
	if renew {
		slog.Debug("Renewing client certificate")
		if err := renewCertificate(ctx, c); err != nil {
			return err
		}
	}
	cert, err := os.ReadFile(c.userCrt)
	if err != nil {
		return fmt.Errorf("Unable to read %s: %w", c.userCrt, err)
	}
	key, err := os.ReadFile(c.userKey)
	if err != nil {
		return fmt.Errorf("Unable to read %s: %w", c.userKey, err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(&clientauth.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &clientauth.ExecCredentialStatus{
			ClientCertificateData: string(cert),
			ClientKeyData:         string(key),
		},
	})
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

func renewCertificate(ctx context.Context, c *Config) error {
	root, err := os.ReadFile(c.clientCACrt)
	if err != nil {
		return fmt.Errorf("Unable to read %s, has `k8sss setup` been run for this cluster?: %w", c.clientCACrt, err)
	}
	cred, err := issueCertificate(ctx, c, root)
	if err != nil {
		return err
	}
	return writeCredential(c, cred)
}

// credential is an issued client certificate with its key, both PEM encoded.
type credential struct {
	chain []byte
	key   []byte
	leaf  *x509.Certificate
}

// issueCertificate requests a client certificate for a key it generates from
// the CA, trusting root for the connection to it.
func issueCertificate(ctx context.Context, c *Config, root []byte) (*credential, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate a client key: %w", err)
	}
	csr, err := x509util.CreateCertificateRequest(c.Username, []string{c.Username}, private)
	if err != nil {
		return nil, fmt.Errorf("Unable to create a certificate request: %w", err)
	}
	chain, err := signRequest(ctx, c, root, csr)
	if err != nil {
		return nil, err
	}
	leaf, err := pemutil.ParseCertificate(chain)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse the issued certificate: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("Unable to encode the client key: %w", err)
	}
	return &credential{
		chain: chain,
		key:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		leaf:  leaf,
	}, nil
}

// Sign implements `k8sss sign`: it has the CA issue a certificate for the PEM
// certificate request read from in and writes the chain to out. The request
// only supplies the key; client.tpl takes the common name and the groups from
// the token.
func Sign(ctx context.Context, c *Config, in io.Reader, out io.Writer) error {
	root, err := os.ReadFile(c.clientCACrt)
	if err != nil {
		return fmt.Errorf("Unable to read %s, has `k8sss setup` been run for this cluster?: %w", c.clientCACrt, err)
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("Unable to read the certificate request: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("No PEM certificate request on stdin")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("Unable to parse the certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("The certificate request's signature doesn't verify: %w", err)
	}
	chain, err := signRequest(ctx, c, root, csr)
	if err != nil {
		return err
	}
	_, err = out.Write(chain)
	return err
}

// signRequest has the CA sign csr for c's username and groups, trusting root
// for the connection to it, and returns the issued chain.
func signRequest(ctx context.Context, c *Config, root []byte, csr *x509.CertificateRequest) ([]byte, error) {
	groups, err := c.GroupList()
	if err != nil {
		return nil, err
	}
	client, err := ca.NewClient(c.CAURL, ca.WithCABundle(root))
	if err != nil {
		return nil, fmt.Errorf("Unable to reach the CA at %s: %w", c.CAURL, err)
	}
	key, err := openSigningKey(c.KeyURI)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	var resp *api.SignResponse
	for remaining := renewAttempts - 1; ; remaining-- {
		// The CA remembers every token it has seen, so each attempt needs a
		// freshly minted one.
		ott, err := key.token(c.CAURL, c.Username, groups, csr)
		if err != nil {
			return nil, err
		}
		resp, err = client.SignWithContext(ctx, &api.SignRequest{
			CsrPEM: api.CertificateRequest{CertificateRequest: csr},
			OTT:    ott,
		})
		if err == nil {
			break
		}
		if remaining <= 0 {
			return nil, fmt.Errorf("Failed to issue kube-api certificate (aborting):\n%w", err)
		}
		slog.Error(fmt.Sprintf("Failed to issue kube-api certificate (%d tries remaining):\n%s", remaining, err))
		time.Sleep(renewBackoff)
	}
	return certChain(resp)
}

func writeCredential(c *Config, cred *credential) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("Unable to create %s: %w", c.dir, err)
	}
	if err := os.WriteFile(c.userKey, cred.key, 0o600); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.userKey, err)
	}
	// Written last: a certificate on disk is taken to mean its key is there too.
	if err := os.WriteFile(c.userCrt, cred.chain, 0o600); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.userCrt, err)
	}
	return nil
}

// certChain serialises the issued chain the same way `step ca certificate`
// writes it, so the file holds what step would have put there.
func certChain(resp *api.SignResponse) ([]byte, error) {
	chain := resp.CertChainPEM
	if len(chain) == 0 {
		chain = []api.Certificate{resp.ServerPEM, resp.CaPEM}
	}
	var out []byte
	for _, cert := range chain {
		if cert.Certificate == nil {
			continue
		}
		block, err := pemutil.Serialize(cert.Certificate)
		if err != nil {
			return nil, fmt.Errorf("Unable to serialize the issued certificate: %w", err)
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("The CA returned an empty certificate chain")
	}
	return out, nil
}
