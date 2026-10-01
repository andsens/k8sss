package k8sss

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const dialTimeout = 30 * time.Second

// Setup establishes trust with a cluster and adds it to the kubeconfig.
func Setup(ctx context.Context, c *Config) error {
	serverCA, err := fetchServerCA(ctx, c.KubeAPIURL)
	if err != nil {
		return fmt.Errorf("Unable to retrieve kube-api server certificate from %s: %w", c.KubeAPIURL, err)
	}
	if err := confirmServerCA(c, serverCA); err != nil {
		return err
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("Unable to create %s: %w", c.dir, err)
	}
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw})
	if err := os.WriteFile(c.serverCACrt, serverCAPEM, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.serverCACrt, err)
	}

	slog.Info("Downloading Kubernetes API Client CA certificate")
	clientCA, err := fetchCARoots(ctx, c.CAURL)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.clientCACrt, clientCA, 0o644); err != nil {
		return fmt.Errorf("Unable to write %s: %w", c.clientCACrt, err)
	}

	slog.Info("Setting up " + abbreviateHome(c.kubeconfig))
	if err := writeKubeconfig(c, serverCAPEM); err != nil {
		return err
	}
	// Any certificate left from a previous setup was issued by a CA we have
	// just replaced, so it is no longer worth keeping.
	for _, path := range []string{c.userCrt, c.userKey} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("Unable to remove %s: %w", path, err)
		}
	}
	return nil
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

// fetchCARoots downloads the CA's root bundle, which for k8sss is the
// Kubernetes client CA. This is the one unverified request k8sss makes: the CA
// client needs a root before it can verify anything, and there is nothing to
// check this one against. It is the same request `step ca root` makes without
// a fingerprint.
func fetchCARoots(ctx context.Context, caURL string) ([]byte, error) {
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
	if block, _ := pem.Decode(body); block == nil {
		return nil, fmt.Errorf("The CA did not return a PEM encoded root certificate")
	}
	return body, nil
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
