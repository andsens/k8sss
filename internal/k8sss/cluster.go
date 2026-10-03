package k8sss

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const dialTimeout = 30 * time.Second

// Setup establishes trust with a cluster and adds it to the kubeconfig.
//
// The kube-api server CA is confirmed by the user. The client CA cannot be
// checked the same way, so it is only trusted once a certificate issued
// through it chains to it and is accepted by the kube-api server. Nothing is
// written before both checks pass.
func Setup(ctx context.Context, c *Config) error {
	// The kube-api server check below means nothing over plain HTTP.
	if parsed, err := url.Parse(c.KubeAPIURL); err != nil || parsed.Scheme != "https" {
		return fmt.Errorf("KUBEAPI_URL '%s' must be an https:// URL", c.KubeAPIURL)
	}
	serverCA, err := fetchServerCA(ctx, c.KubeAPIURL)
	if err != nil {
		return fmt.Errorf("Unable to retrieve kube-api server certificate from %s: %w", c.KubeAPIURL, err)
	}
	if err := confirmServerCA(c, serverCA); err != nil {
		return err
	}

	slog.Info("Downloading Kubernetes API Client CA certificate")
	clientCA, err := fetchCARoot(ctx, c.CAURL)
	if err != nil {
		return err
	}
	clientCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw})

	slog.Info("Issuing a client certificate to verify the client CA with")
	cred, err := issueCertificate(ctx, c, clientCAPEM)
	if err != nil {
		return err
	}
	untrusted := func(reason string) error {
		return fmt.Errorf("The CA at %s is not the one the kube-api server at %s trusts: %s. "+
			"Either --ca-url is misconfigured (it may point at another cluster), "+
			"or the connection to the CA is being intercepted", c.CAURL, c.KubeAPIURL, reason)
	}
	// Without this, a forged root in front of the real CA would pass the
	// kube-api server check and stay trusted.
	if err := verifyClientCert(cred, clientCA); err != nil {
		return untrusted(fmt.Sprintf("the issued certificate does not chain to its root (%s)", err))
	}
	slog.Info("Checking that the kube-api server accepts the issued certificate")
	username, err := whoAmI(ctx, c.KubeAPIURL, serverCA, cred)
	if err != nil {
		return err
	}
	if username == "" {
		return untrusted("the kube-api server rejected the issued certificate")
	}
	if username != c.Username {
		return untrusted(fmt.Sprintf("the kube-api server took the issued certificate for %q", username))
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("Unable to create %s: %w", c.dir, err)
	}
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw})
	if err := os.WriteFile(c.serverCACrt, serverCAPEM, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.serverCACrt, err)
	}
	if err := os.WriteFile(c.clientCACrt, clientCAPEM, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.clientCACrt, err)
	}
	// Kept, so kubectl does not need another signature right away.
	if err := writeCredential(c, cred); err != nil {
		return err
	}
	slog.Info("Setting up " + abbreviateHome(c.kubeconfig))
	return writeKubeconfig(c, serverCAPEM)
}

// confirmServerCA is the trust-on-first-use step: the fingerprint of the CA
// behind the Kubernetes API server is shown to the user the first time, and
// checked against the stored copy on every later run.
func confirmServerCA(c *Config, serverCA *x509.Certificate) error {
	remote := x509util.Fingerprint(serverCA)
	saved, err := pemutil.ReadCertificate(c.serverCACrt)
	switch {
	case err == nil:
		slog.Info("Checking existing Kubernetes API server CA certificate")
		savedFingerprint := x509util.Fingerprint(saved)
		if savedFingerprint == remote {
			return nil
		}
		fmt.Fprintf(os.Stderr, "Saved fingerprint:  %s\n", savedFingerprint)
		fmt.Fprintf(os.Stderr, "Remote fingerprint: %s\n", remote)
		slog.Error("The saved Kubernetes API server CA certificate fingerprint does not match the one from the server!")
		if !confirm("Are you sure you want to continue? [y/N]") {
			return fmt.Errorf("User aborted operation")
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
		slog.Warn("No trust has been established with this Kubernetes cluster yet.\n" +
			"The root certificate fingerprint is " + remote)
		if !confirm("Do you want to establish that trust now? [y/N]") {
			return fmt.Errorf("User aborted operation")
		}
		return nil
	default:
		return fmt.Errorf("Unable to read %s: %w", c.serverCACrt, err)
	}
}

// fetchServerCA connects to the Kubernetes API server and returns the last
// certificate it presents, which is the CA that issued its serving
// certificate.
func fetchServerCA(ctx context.Context, kubeAPIURL string) (*x509.Certificate, error) {
	parsed, err := url.Parse(kubeAPIURL)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse '%s': %w", kubeAPIURL, err)
	}
	address := parsed.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "443")
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		//nolint:gosec // the fingerprint is shown to the user to confirm instead
		Config: &tls.Config{InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("the server presented no certificates")
	}
	return chain[len(chain)-1], nil
}

// fetchCARoot downloads the CA's root, which for k8sss is the Kubernetes
// client CA. The request is unverified, since the CA client needs a root
// before it can verify anything; Setup checks the root afterwards. It is the
// same request `step ca root` makes without a fingerprint.
func fetchCARoot(ctx context.Context, caURL string) (*x509.Certificate, error) {
	client := &http.Client{
		Timeout: dialTimeout,
		Transport: &http.Transport{
			//nolint:gosec // no root is known until this call returns one
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL+"/roots.pem", nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to build a request for the CA roots: %w", err)
	}
	resp, err := client.Do(request)
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
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("The CA did not return a PEM encoded root certificate")
	}
	// A second root could be a forged one riding along with the real one,
	// and the checks in Setup would not notice it.
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("The CA at %s returned more than its root certificate, "+
			"k8sss expects the Kubernetes client CA on its own", caURL)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse the CA root: %w", err)
	}
	return root, nil
}

// verifyClientCert checks that cred chains to root as a client certificate.
func verifyClientCert(cred *credential, root *x509.Certificate) error {
	chain, err := pemutil.ParseCertificateBundle(cred.chain)
	if err != nil {
		return err
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err = cred.leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// whoAmI is `kubectl auth whoami`: it asks the kube-api server which user it
// takes the holder of cred to be. An empty username means the server refused
// the request as unauthenticated.
func whoAmI(ctx context.Context, kubeAPIURL string, serverCA *x509.Certificate, cred *credential) (string, error) {
	pair, err := tls.X509KeyPair(cred.chain, cred.key)
	if err != nil {
		return "", fmt.Errorf("Unable to load the issued certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(serverCA)
	client := &http.Client{
		Timeout: dialTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{pair},
		}},
	}
	body, err := json.Marshal(&authv1.SelfSubjectReview{TypeMeta: metav1.TypeMeta{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "SelfSubjectReview",
	}})
	if err != nil {
		return "", fmt.Errorf("Unable to encode a SelfSubjectReview: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(kubeAPIURL, "/")+"/apis/authentication.k8s.io/v1/selfsubjectreviews",
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("Unable to build a SelfSubjectReview request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("Unable to reach the kube-api server at %s: %w", kubeAPIURL, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", nil
	default:
		return "", fmt.Errorf("The kube-api server answered %s to a SelfSubjectReview", resp.Status)
	}
	var review authv1.SelfSubjectReview
	if err := json.NewDecoder(resp.Body).Decode(&review); err != nil {
		return "", fmt.Errorf("Unable to parse the SelfSubjectReview: %w", err)
	}
	return review.Status.UserInfo.Username, nil
}

// List names every cluster that has been set up, which is one directory per
// Kubernetes API server hostname.
func List(c *Config) error {
	entries, err := os.ReadDir(c.configDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Unable to read %s: %w", c.configDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			fmt.Println(entry.Name())
		}
	}
	return nil
}

// Remove drops the stored certificates along with the context and the cluster
// and user it refers to.
func Remove(c *Config) error {
	if c.KubeAPIHostname == "" {
		return fmt.Errorf("KUBEAPI_HOSTNAME must not be empty")
	}
	if err := os.RemoveAll(c.dir); err != nil {
		return fmt.Errorf("Unable to remove %s: %w", c.dir, err)
	}
	config, err := loadKubeconfig(c.kubeconfig)
	if err != nil {
		return err
	}
	context, ok := config.Contexts[c.Context]
	if !ok {
		slog.Warn(fmt.Sprintf("Unable to find the context '%s' in your kubeconfig. "+
			"You will have to remove the user, cluster, and context manually", c.Context))
		return nil
	}
	delete(config.Clusters, context.Cluster)
	delete(config.AuthInfos, context.AuthInfo)
	delete(config.Contexts, c.Context)
	if config.CurrentContext == c.Context {
		config.CurrentContext = ""
	}
	if err := clientcmd.WriteToFile(*config, c.kubeconfig); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.kubeconfig, err)
	}
	return nil
}

// writeKubeconfig adds (or updates) the cluster, user and context for this
// Kubernetes API server, leaving every other entry in the file alone.
func writeKubeconfig(c *Config, serverCA []byte) error {
	config, err := loadKubeconfig(c.kubeconfig)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Unable to determine the path to k8sss: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}

	cluster, ok := config.Clusters[c.Cluster]
	if !ok {
		cluster = api.NewCluster()
	}
	cluster.Server = c.KubeAPIURL
	cluster.CertificateAuthorityData = serverCA
	cluster.CertificateAuthority = ""
	config.Clusters[c.Cluster] = cluster
	slog.Info(fmt.Sprintf("Cluster %q set", c.Cluster))

	userName := c.Username + "@" + c.Cluster
	authInfo, ok := config.AuthInfos[userName]
	if !ok {
		authInfo = api.NewAuthInfo()
	}
	authInfo.Exec = &api.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Command:    executable,
		Args:       ExecArgs(&c.Params),
	}
	config.AuthInfos[userName] = authInfo
	slog.Info(fmt.Sprintf("User %q set", userName))

	context, ok := config.Contexts[c.Context]
	if !ok {
		context = api.NewContext()
	}
	context.Cluster = c.Cluster
	context.AuthInfo = userName
	config.Contexts[c.Context] = context
	slog.Info(fmt.Sprintf("Context %q set", c.Context))

	// WriteToFile creates the directory and writes with 0600 itself.
	if err := clientcmd.WriteToFile(*config, c.kubeconfig); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.kubeconfig, err)
	}
	return nil
}

func loadKubeconfig(path string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(path)
	if os.IsNotExist(err) {
		return api.NewConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("Unable to read %s: %w", path, err)
	}
	return config, nil
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
