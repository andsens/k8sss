package k8sss

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

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
