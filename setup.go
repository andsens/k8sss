package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const dialTimeout = 30 * time.Second

func setupCluster(p *params, pth *paths) error {
	serverCA, err := fetchServerCA(p.KubeAPIURL)
	if err != nil {
		return fmt.Errorf("Unable to retrieve kube-api server certificate from %s: %w", p.KubeAPIURL, err)
	}
	remoteFingerprint := fingerprint(serverCA)

	saved, err := os.ReadFile(pth.serverCACrt)
	switch {
	case err == nil:
		slog.Info("Checking existing Kubernetes API server CA certificate")
		savedFingerprint, err := fingerprintPEM(saved)
		if err != nil {
			return fmt.Errorf("Unable to read %s: %w", pth.serverCACrt, err)
		}
		if savedFingerprint != remoteFingerprint {
			fmt.Fprintf(os.Stderr, "Saved fingerprint:  %s\n", savedFingerprint)
			fmt.Fprintf(os.Stderr, "Remote fingerprint: %s\n", remoteFingerprint)
			slog.Error("The saved Kubernetes API server CA certificate fingerprint does not match the one from the server!")
			if !confirm("Are you sure you want to continue? [y/N]") {
				return fmt.Errorf("User aborted operation")
			}
		}
	case os.IsNotExist(err):
		slog.Warn(fmt.Sprintf("No trust has been established with this Kubernetes cluster yet.\nThe root certificate fingerprint is %s", remoteFingerprint))
		if !confirm("Do you want to establish that trust now? [y/N]") {
			return fmt.Errorf("User aborted operation")
		}
	default:
		return fmt.Errorf("Unable to read %s: %w", pth.serverCACrt, err)
	}

	if err := os.MkdirAll(pth.dir, 0o700); err != nil {
		return fmt.Errorf("Unable to create %s: %w", pth.dir, err)
	}
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw})
	if err := os.WriteFile(pth.serverCACrt, serverCAPEM, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", pth.serverCACrt, err)
	}

	slog.Info("Downloading Kubernetes API Client CA certificate")
	clientCA, err := fetchRoots(p.CAURL)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pth.clientCACrt, clientCA, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", pth.clientCACrt, err)
	}

	slog.Info(fmt.Sprintf("Setting up %s", abbreviateHome(pth.kubeconfig)))
	if err := writeKubeconfig(p, pth, serverCAPEM); err != nil {
		return err
	}
	// Any certificate left over from a previous setup was issued for a CA we
	// have just replaced, so it is no longer worth keeping.
	for _, path := range []string{pth.userCrt, pth.userKey} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("Unable to remove %s: %w", path, err)
		}
	}
	return nil
}

// fetchServerCA connects to the Kubernetes API server and returns the last
// certificate it presents, which is the CA that issued its serving
// certificate.
func fetchServerCA(kubeAPIURL string) (*x509.Certificate, error) {
	parsed, err := url.Parse(kubeAPIURL)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse '%s': %w", kubeAPIURL, err)
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(address, "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", address, &tls.Config{
		//nolint:gosec // the fingerprint is shown to the user to confirm instead
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("the server presented no certificates")
	}
	return chain[len(chain)-1], nil
}

// fingerprint is the hex encoded SHA-256 of the certificate in DER form, the
// same value `step certificate fingerprint` prints.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func fingerprintPEM(data []byte) (string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM encoded certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return fingerprint(cert), nil
}

var affirmative = regexp.MustCompile(`^[Yy](es)?$`)

// confirm asks a yes/no question, defaulting to no on anything else.
func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && answer == "" {
		fmt.Fprintln(os.Stderr)
		return false
	}
	return affirmative.MatchString(strings.TrimSpace(answer))
}

func abbreviateHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.Join("~", rel)
	}
	return path
}
