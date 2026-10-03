package k8sss

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.step.sm/crypto/pemutil"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func testParams() *Params {
	return &Params{
		KubeAPIURL:      "https://nas:6443",
		KubeAPIHostname: "nas",
		CAURL:           "https://nas:9000",
		KeyURI:          "sshagentkms:tester@workstation",
		Username:        "system:admin",
		Context:         "nas",
		Cluster:         "nas",
	}
}

// testHome points the config and kubeconfig paths at a temporary directory, so
// the tests exercise the real path layout.
func testHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// testConfig is the command line of testParams with its paths worked out.
func testConfig(t *testing.T) *Config {
	t.Helper()
	config, err := testParams().Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	return config
}

// The hostname and the username become path elements, and Remove deletes the
// directory the hostname names.
func TestConfigRejectsPathsInNamesUsedAsDirectories(t *testing.T) {
	testHome(t)
	for _, tc := range []struct{ hostname, username string }{
		{"../../etc", "system:admin"},
		{"..", "system:admin"},
		{".", "system:admin"},
		{"a/b", "system:admin"},
		{"nas", "../../root"},
		{"nas", "a/b"},
	} {
		params := testParams()
		params.KubeAPIHostname = tc.hostname
		params.Username = tc.username
		if _, err := params.Config(); err == nil {
			t.Errorf("hostname %q username %q was accepted", tc.hostname, tc.username)
		}
	}
}

func TestConfigResolvesThePaths(t *testing.T) {
	home := testHome(t)
	config := testConfig(t)
	dir := filepath.Join(home, ".config", "k8sss", "nas")
	for _, tc := range []struct{ name, got, want string }{
		{"configDir", config.configDir, filepath.Join(home, ".config", "k8sss")},
		{"dir", config.dir, dir},
		{"serverCACrt", config.serverCACrt, filepath.Join(dir, "server-ca.crt")},
		{"clientCACrt", config.clientCACrt, filepath.Join(dir, "client-ca.crt")},
		{"userCrt", config.userCrt, filepath.Join(dir, "system:admin.crt")},
		{"userKey", config.userKey, filepath.Join(dir, "system:admin.key")},
		{"kubeconfig", config.kubeconfig, filepath.Join(home, ".kube", "config.yaml")},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestWriteKubeconfigAddsTheClusterUserAndContext(t *testing.T) {
	testHome(t)
	c := testConfig(t)
	if err := writeKubeconfig(c, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}
	config, err := clientcmd.LoadFromFile(c.kubeconfig)
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}

	cluster, ok := config.Clusters["nas"]
	if !ok {
		t.Fatal("no cluster was written")
	}
	if cluster.Server != "https://nas:6443" {
		t.Errorf("server: got %q", cluster.Server)
	}
	if len(cluster.CertificateAuthorityData) == 0 {
		t.Error("the CA certificate was not embedded")
	}

	authInfo, ok := config.AuthInfos["system:admin@nas"]
	if !ok || authInfo.Exec == nil {
		t.Fatal("no user with an exec credential plugin was written")
	}
	if authInfo.Exec.APIVersion != "client.authentication.k8s.io/v1beta1" {
		t.Errorf("exec api version: got %q", authInfo.Exec.APIVersion)
	}
	// The plugin invocation has to come from the shared builder, which is what
	// main's tests parse back to close the loop across the package boundary.
	if !slices.Equal(authInfo.Exec.Args, ExecArgs(&c.Params)) {
		t.Errorf("exec args:\n got %q\nwant %q", authInfo.Exec.Args, ExecArgs(&c.Params))
	}
	want := []string{"cert", "-ksshagentkms:tester@workstation", "-usystem:admin", "-chttps://nas:9000", "nas"}
	if !slices.Equal(authInfo.Exec.Args, want) {
		t.Errorf("exec args:\n got %q\nwant %q", authInfo.Exec.Args, want)
	}

	context, ok := config.Contexts["nas"]
	if !ok {
		t.Fatal("no context was written")
	}
	if context.Cluster != "nas" || context.AuthInfo != "system:admin@nas" {
		t.Errorf("context points at %q/%q", context.Cluster, context.AuthInfo)
	}
}

// Editing one cluster must not disturb anything else in the file, the way
// `kubectl config set-cluster` would not.
func TestWriteKubeconfigLeavesOtherEntriesAlone(t *testing.T) {
	testHome(t)
	c := testConfig(t)
	existing := api.NewConfig()
	existing.Clusters["other"] = &api.Cluster{Server: "https://other:6443"}
	existing.Contexts["other"] = &api.Context{Cluster: "other", AuthInfo: "someone"}
	existing.AuthInfos["someone"] = &api.AuthInfo{Token: "secret"}
	existing.Contexts["nas"] = &api.Context{Cluster: "nas", AuthInfo: "old", Namespace: "kube-system"}
	existing.CurrentContext = "other"
	if err := clientcmd.WriteToFile(*existing, c.kubeconfig); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}

	if err := writeKubeconfig(c, []byte("ca")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}
	config, err := clientcmd.LoadFromFile(c.kubeconfig)
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	if _, ok := config.Clusters["other"]; !ok {
		t.Error("an unrelated cluster was removed")
	}
	if config.CurrentContext != "other" {
		t.Errorf("current context changed to %q", config.CurrentContext)
	}
	if got := config.Contexts["nas"].Namespace; got != "kube-system" {
		t.Errorf("the namespace of the existing context was lost: %q", got)
	}
}

func TestRemoveDeletesEverythingItAdded(t *testing.T) {
	testHome(t)
	c := testConfig(t)
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		t.Fatalf("creating cluster directory: %v", err)
	}
	if err := writeKubeconfig(c, []byte("ca")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}

	if err := Remove(c); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(c.dir); !os.IsNotExist(err) {
		t.Error("the cluster directory was left behind")
	}
	config, err := clientcmd.LoadFromFile(c.kubeconfig)
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	if len(config.Clusters) != 0 || len(config.AuthInfos) != 0 || len(config.Contexts) != 0 {
		t.Errorf("entries were left behind: %+v", config)
	}
}

// Refusing an empty hostname keeps Remove from wiping the whole config
// directory.
func TestRemoveRefusesAnEmptyHostname(t *testing.T) {
	home := testHome(t)
	params := testParams()
	params.KubeAPIHostname = ""
	c, err := params.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if err := Remove(c); err == nil {
		t.Error("expected an error for an empty hostname")
	}
	if _, err := os.Stat(home); err != nil {
		t.Error("the home directory was removed")
	}
}

func TestListOnAMissingDirectory(t *testing.T) {
	testHome(t)
	if err := List(testConfig(t)); err != nil {
		t.Errorf("List: %v", err)
	}
}

func TestListNamesTheConfiguredClusters(t *testing.T) {
	home := testHome(t)
	for _, name := range []string{"nas", "kube.example.com"} {
		if err := os.MkdirAll(filepath.Join(home, ".config", "k8sss", name), 0o700); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}
	if err := List(testConfig(t)); err != nil {
		t.Errorf("List: %v", err)
	}
}

// startAPIServer stands in for the kube-api server's SelfSubjectReview
// endpoint. Like the real one, it asks for a client certificate without
// requiring one, and treats a certificate that does not chain to clientCA as
// no certificate at all: a 401, or system:anonymous when anonymous is set.
func startAPIServer(t *testing.T, serverCA, clientCA *testCA, anonymous bool) string {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(clientCA.cert)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/selfsubjectreviews", func(w http.ResponseWriter, r *http.Request) {
		review := authv1.SelfSubjectReview{}
		review.APIVersion, review.Kind = "authentication.k8s.io/v1", "SelfSubjectReview"
		peers := r.TLS.PeerCertificates
		intermediates := x509.NewCertPool()
		for _, cert := range peers[min(1, len(peers)):] {
			intermediates.AddCert(cert)
		}
		switch {
		case len(peers) > 0 && verifies(peers[0], roots, intermediates):
			review.Status.UserInfo.Username = peers[0].Subject.CommonName
		case anonymous:
			review.Status.UserInfo.Username = "system:anonymous"
		default:
			http.Error(w, `{"kind":"Status","code":401}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(&review)
	})
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCA.cert.Raw}, PrivateKey: serverCA.key}},
		ClientAuth:   tls.RequestClientCert,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

func verifies(leaf *x509.Certificate, roots, intermediates *x509.CertPool) bool {
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// startInterceptor sits in front of a CA the way someone intercepting port
// 9000 would: it terminates TLS with a forged root, answers /roots.pem itself
// and relays signing requests to upstream.
func startInterceptor(t *testing.T, forged *testCA, roots string, upstream string) string {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parsing %s: %v", upstream, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	//nolint:gosec // the upstream is a test CA
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	mux := http.NewServeMux()
	mux.HandleFunc("/roots.pem", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, roots) })
	mux.Handle("/", proxy)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{forged.cert.Raw},
		PrivateKey:  forged.key,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// answerPrompts feeds the confirmation prompts.
func answerPrompts(t *testing.T, answers string) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	io.WriteString(write, answers)
	write.Close()
	original := os.Stdin
	os.Stdin = read
	t.Cleanup(func() { os.Stdin = original; read.Close() })
}

func setupConfig(t *testing.T, kubeAPIURL, caURL string) *Config {
	t.Helper()
	params := testParams()
	params.KubeAPIURL, params.CAURL = kubeAPIURL, caURL
	config, err := params.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	return config
}

// snapshot reads every file setup writes.
func snapshot(t *testing.T, c *Config) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, path := range []string{c.serverCACrt, c.clientCACrt, c.userCrt, c.userKey, c.kubeconfig} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		files[path] = string(data)
	}
	return files
}

// A setup cluster: the client CA behind step-ca and the kube-api server that
// trusts it, with setup already run against both.
type setupCluster struct {
	signer   crypto.Signer
	clientCA *testCA
	serverCA *testCA
	ca       *standInCA
	config   *Config
}

func newSetupCluster(t *testing.T) *setupCluster {
	t.Helper()
	signer := testKeys(t)["ecdsa"]
	const comment = "tester@workstation"
	t.Setenv("SSH_AUTH_SOCK", startAgent(t, signer, comment))
	testHome(t)

	cluster := &setupCluster{signer: signer, clientCA: newTestCA(t), serverCA: newTestCA(t)}
	cluster.ca = startCA(t, cluster.clientCA, signer.Public())
	cluster.config = setupConfig(t,
		startAPIServer(t, cluster.serverCA, cluster.clientCA, false),
		cluster.ca.url)
	cluster.config.KeyURI = "sshagentkms:" + comment
	answerPrompts(t, "y\n")
	if err := Setup(context.Background(), cluster.config); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return cluster
}

func TestSetupWritesTheCertificatesAndKubeconfig(t *testing.T) {
	cluster := newSetupCluster(t)
	c := cluster.config

	for path, want := range map[string]*x509.Certificate{
		c.serverCACrt: cluster.serverCA.cert,
		c.clientCACrt: cluster.clientCA.cert,
	} {
		got, err := pemutil.ReadCertificate(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !got.Equal(want) {
			t.Errorf("%s holds the wrong certificate", path)
		}
	}
	// The certificate issued to check the client CA is kept, so the first
	// kubectl call does not need another signature.
	if _, err := tls.LoadX509KeyPair(c.userCrt, c.userKey); err != nil {
		t.Errorf("the issued certificate was not kept: %v", err)
	}
	if renew, err := needsRenewal(c.userCrt); err != nil || renew {
		t.Errorf("the kept certificate is due for renewal: (%v, %v)", renew, err)
	}
	config, err := clientcmd.LoadFromFile(c.kubeconfig)
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	if got := config.Clusters["nas"].Server; got != c.KubeAPIURL {
		t.Errorf("server: got %q, want %q", got, c.KubeAPIURL)
	}
}

// Each case re-runs setup against a cluster that was set up correctly, with
// the CA swapped for something the kube-api server does not trust. Setup has
// to fail at the right check and leave the working setup alone.
func TestSetupRejectsAClientCATheServerDoesNotTrust(t *testing.T) {
	for _, tc := range []struct {
		name      string
		anonymous bool
		caURL     func(t *testing.T, cluster *setupCluster, forged *testCA) string
		want      string
	}{{
		name: "a forged CA that signs the CSR itself",
		caURL: func(t *testing.T, cluster *setupCluster, forged *testCA) string {
			return startCA(t, forged, cluster.signer.Public()).url
		},
		want: "rejected the issued certificate",
	}, {
		name:      "a forged CA and an apiserver that lets anonymous requests through",
		anonymous: true,
		caURL: func(t *testing.T, cluster *setupCluster, forged *testCA) string {
			return startCA(t, forged, cluster.signer.Public()).url
		},
		want: `took the issued certificate for "system:anonymous"`,
	}, {
		name: "a forged root in front of the real CA",
		caURL: func(t *testing.T, cluster *setupCluster, forged *testCA) string {
			return startInterceptor(t, forged, encodeCert(forged.cert), cluster.ca.url)
		},
		want: "does not chain to its root",
	}, {
		name: "a forged root bundled with the real one",
		caURL: func(t *testing.T, cluster *setupCluster, forged *testCA) string {
			return startInterceptor(t, forged,
				encodeCert(cluster.clientCA.cert)+encodeCert(forged.cert), cluster.ca.url)
		},
		want: "more than its root certificate",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newSetupCluster(t)
			before := snapshot(t, cluster.config)

			c := *cluster.config
			c.KubeAPIURL = startAPIServer(t, cluster.serverCA, cluster.clientCA, tc.anonymous)
			c.CAURL = tc.caURL(t, cluster, newTestCA(t))
			err := Setup(context.Background(), &c)
			if err == nil {
				t.Fatal("Setup trusted a CA the kube-api server does not")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Setup failed for the wrong reason:\n got %v\nwant %q", err, tc.want)
			}
			if after := snapshot(t, cluster.config); !maps.Equal(before, after) {
				t.Error("the failed setup changed the files of the earlier one")
			}
		})
	}
}

func TestSetupRefusesPlainHTTP(t *testing.T) {
	testHome(t)
	c := setupConfig(t, "http://nas:6443", "https://nas:9000")
	if err := Setup(context.Background(), c); err == nil {
		t.Error("Setup accepted an http:// kube-api URL")
	}
}
