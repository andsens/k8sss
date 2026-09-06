package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	docopt "github.com/docopt/docopt-go"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func testParams() *params {
	return &params{
		KubeAPIURL:      "https://nas:6443",
		KubeAPIHostname: "nas",
		CAURL:           "https://nas:9000",
		KeyURI:          "sshagentkms:tester@workstation",
		Username:        "system:admin",
		Context:         "nas",
		Cluster:         "nas",
	}
}

func TestWriteKubeconfigAddsTheClusterUserAndContext(t *testing.T) {
	dir := t.TempDir()
	pth := paths{kubeconfig: filepath.Join(dir, "config.yaml")}
	p := testParams()

	if err := writeKubeconfig(p, &pth, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")); err != nil {
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
		t.Errorf("server: got %q, want %q", cluster.Server, "https://nas:6443")
	}
	if len(cluster.CertificateAuthorityData) == 0 {
		t.Error("the CA certificate was not embedded")
	}

	authInfo, ok := config.AuthInfos["system:admin@nas"]
	if !ok {
		t.Fatal("no user was written")
	}
	if authInfo.Exec == nil {
		t.Fatal("the user has no exec credential plugin")
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
	opts, err := docopt.ParseArgs(usage, authInfo.Exec.Args, "")
	if err != nil {
		t.Fatalf("k8sss cannot parse the arguments it wrote: %v", err)
	}
	var parsed params
	if err := opts.Bind(&parsed); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if err := parsed.resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !parsed.Cert {
		t.Error("the written arguments do not select the cert command")
	}
	if parsed.KeyURI != p.KeyURI || parsed.Username != p.Username ||
		parsed.CAURL != p.CAURL || parsed.KubeAPIHostname != p.KubeAPIHostname {
		t.Errorf("round trip lost something: got %+v, want keyuri=%q username=%q ca=%q host=%q",
			parsed, p.KeyURI, p.Username, p.CAURL, p.KubeAPIHostname)
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
	dir := t.TempDir()
	pth := paths{kubeconfig: filepath.Join(dir, "config.yaml")}

	existing := api.NewConfig()
	existing.Clusters["other"] = &api.Cluster{Server: "https://other:6443"}
	existing.Contexts["other"] = &api.Context{Cluster: "other", AuthInfo: "someone"}
	existing.AuthInfos["someone"] = &api.AuthInfo{Token: "secret"}
	existing.Contexts["nas"] = &api.Context{Cluster: "nas", AuthInfo: "old", Namespace: "kube-system"}
	existing.CurrentContext = "other"
	if err := clientcmd.WriteToFile(*existing, pth.kubeconfig); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}

	if err := writeKubeconfig(testParams(), &pth, []byte("ca")); err != nil {
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

func TestRemoveClusterDeletesEverythingItAdded(t *testing.T) {
	dir := t.TempDir()
	pth := paths{
		dir:        filepath.Join(dir, "nas"),
		kubeconfig: filepath.Join(dir, "config.yaml"),
	}
	if err := os.MkdirAll(pth.dir, 0o700); err != nil {
		t.Fatalf("creating cluster directory: %v", err)
	}
	p := testParams()
	if err := writeKubeconfig(p, &pth, []byte("ca")); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}

	if err := removeCluster(p, &pth, dir); err != nil {
		t.Fatalf("removeCluster: %v", err)
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

// Refusing an empty hostname keeps rm from wiping the whole config directory.
func TestRemoveClusterRefusesAnEmptyHostname(t *testing.T) {
	dir := t.TempDir()
	p := testParams()
	p.KubeAPIHostname = ""
	pth := paths{dir: dir, kubeconfig: filepath.Join(dir, "config.yaml")}
	if err := removeCluster(p, &pth, dir); err == nil {
		t.Error("expected an error for an empty hostname")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("the config directory was removed")
	}
}

func TestListClustersOnAMissingDirectory(t *testing.T) {
	if err := listClusters(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Errorf("listClusters: %v", err)
	}
}
