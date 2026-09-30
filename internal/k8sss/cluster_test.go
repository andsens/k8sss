package k8sss

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func clusterParams() *Params {
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

func TestWriteKubeconfigAddsTheClusterUserAndContext(t *testing.T) {
	testHome(t)
	p := clusterParams()
	pth, err := p.paths()
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	if err := writeKubeconfig(p, pth, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}
	config, err := clientcmd.LoadFromFile(pth.kubeconfig)
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
	want := []string{"cert", "-ksshagentkms:tester@workstation", "-usystem:admin", "-chttps://nas:9000", "nas"}
	if !slices.Equal(authInfo.Exec.Args, want) {
		t.Errorf("exec args:\n got %q\nwant %q", authInfo.Exec.Args, want)
	}

	// Feed the arguments that were just written back through the parser. This
	// is the seam kubectl uses, and asserting the shape at both ends
	// separately would not catch the two drifting together.
	parsed, err := parseArgv(authInfo.Exec.Args)
	if err != nil {
		t.Fatalf("k8sss cannot parse the arguments it wrote: %v", err)
	}
	if !parsed.Cert || parsed.KeyURI != p.KeyURI || parsed.Username != p.Username ||
		parsed.CAURL != p.CAURL || parsed.KubeAPIHostname != p.KubeAPIHostname {
		t.Errorf("round trip lost something: %+v", parsed)
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
	p := clusterParams()
	pth, err := p.paths()
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	existing := api.NewConfig()
	existing.Clusters["other"] = &api.Cluster{Server: "https://other:6443"}
	existing.Contexts["other"] = &api.Context{Cluster: "other", AuthInfo: "someone"}
	existing.AuthInfos["someone"] = &api.AuthInfo{Token: "secret"}
	existing.Contexts["nas"] = &api.Context{Cluster: "nas", AuthInfo: "old", Namespace: "kube-system"}
	existing.CurrentContext = "other"
	if err := clientcmd.WriteToFile(*existing, pth.kubeconfig); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}

	if err := writeKubeconfig(p, pth, []byte("ca")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}
	config, err := clientcmd.LoadFromFile(pth.kubeconfig)
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
	p := clusterParams()
	pth, err := p.paths()
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	if err := os.MkdirAll(pth.dir, 0o700); err != nil {
		t.Fatalf("creating cluster directory: %v", err)
	}
	if err := writeKubeconfig(p, pth, []byte("ca")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}

	if err := Remove(p); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(pth.dir); !os.IsNotExist(err) {
		t.Error("the cluster directory was left behind")
	}
	config, err := clientcmd.LoadFromFile(pth.kubeconfig)
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
	p := clusterParams()
	p.KubeAPIHostname = ""
	if err := Remove(p); err == nil {
		t.Error("expected an error for an empty hostname")
	}
	if _, err := os.Stat(home); err != nil {
		t.Error("the home directory was removed")
	}
}

func TestListOnAMissingDirectory(t *testing.T) {
	testHome(t)
	if err := List(clusterParams()); err != nil {
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
	if err := List(clusterParams()); err != nil {
		t.Errorf("List: %v", err)
	}
}
