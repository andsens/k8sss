package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

const caTimeout = 30 * time.Second

// fetchRoots downloads the CA's root bundle over an unverified connection.
// There is nothing to verify against yet, which is why setup makes the user
// confirm the Kubernetes API server fingerprint before it gets this far.
func fetchRoots(caURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: caTimeout,
		Transport: &http.Transport{
			//nolint:gosec // no root is known until this call returns one
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(caURL + "/roots.pem")
	if err != nil {
		return nil, fmt.Errorf("Unable to reach the CA at %s: %w", caURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Unable to read the CA roots: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("The CA returned %s when asked for its roots", resp.Status)
	}
	if block, _ := pem.Decode(body); block == nil {
		return nil, fmt.Errorf("The CA did not return a PEM encoded root certificate")
	}
	return body, nil
}

type signRequest struct {
	CSR string `json:"csr"`
	OTT string `json:"ott"`
}

type signResponse struct {
	Crt       string   `json:"crt"`
	CA        string   `json:"ca"`
	CertChain []string `json:"certChain"`
	// Set on failure instead of the fields above.
	Message string `json:"message"`
}

// signCertificate trades a CSR and a one-time token for a client certificate.
// The connection is verified against the CA's own root, which for k8sss is the
// Kubernetes client CA the CA signs with.
func signCertificate(caURL string, root []byte, csr *x509.CertificateRequest, token string) ([]byte, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, fmt.Errorf("Unable to parse the CA root certificate")
	}
	client := &http.Client{
		Timeout: caTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	body, err := json.Marshal(signRequest{
		CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		OTT: token,
	})
	if err != nil {
		return nil, fmt.Errorf("Unable to encode the signing request: %w", err)
	}
	resp, err := client.Post(caURL+"/1.0/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("Unable to reach the CA at %s: %w", caURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Unable to read the CA response: %w", err)
	}
	var signed signResponse
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, fmt.Errorf("Unable to parse the CA response (%s): %s", resp.Status, raw)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		if signed.Message != "" {
			return nil, fmt.Errorf("The CA refused to issue a certificate (%s): %s", resp.Status, signed.Message)
		}
		return nil, fmt.Errorf("The CA refused to issue a certificate (%s)", resp.Status)
	}
	return clientChain(&signed)
}

// clientChain assembles what the certificate file should hold: the leaf and
// any intermediates, but not the root. A client sends this chain to the
// Kubernetes API server, which already knows the root and does not need a copy.
func clientChain(signed *signResponse) ([]byte, error) {
	chain := signed.CertChain
	if len(chain) == 0 {
		chain = []string{signed.Crt}
	}
	var out []byte
	for i, encoded := range chain {
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			return nil, fmt.Errorf("The CA returned a certificate that is not PEM encoded")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse the issued certificate: %w", err)
		}
		// Anything self-signed is a root; the leaf is kept regardless so a
		// self-signed certificate still produces a usable file.
		if i > 0 && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("The CA returned an empty certificate chain")
	}
	return out, nil
}
