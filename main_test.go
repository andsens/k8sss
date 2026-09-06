package main

import (
	"testing"

	docopt "github.com/docopt/docopt-go"
)

func TestResolveDerivesTheHostnameFromTheURL(t *testing.T) {
	for _, tc := range []struct {
		arg      string
		hostname string
		url      string
	}{
		{"nas:6443", "nas", "https://nas:6443"},
		{"https://nas:6443", "nas", "https://nas:6443"},
		{"http://nas:6443", "nas", "http://nas:6443"},
		{"nas", "nas", "https://nas"},
		{"https://k8s.example.com:6443", "k8s.example.com", "https://k8s.example.com:6443"},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			p := newSetupParams(tc.arg)
			if err := p.resolve(); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if p.KubeAPIHostname != tc.hostname {
				t.Errorf("hostname: got %q, want %q", p.KubeAPIHostname, tc.hostname)
			}
			if p.KubeAPIURL != tc.url {
				t.Errorf("url: got %q, want %q", p.KubeAPIURL, tc.url)
			}
		})
	}
}

func TestResolveExpandsThePlaceholderDefaults(t *testing.T) {
	p := newSetupParams("nas:6443")
	if err := p.resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := "https://nas:9000"; p.CAURL != want {
		t.Errorf("ca-url: got %q, want %q", p.CAURL, want)
	}
	if p.Context != "nas" {
		t.Errorf("context: got %q, want %q", p.Context, "nas")
	}
	if p.Cluster != "nas" {
		t.Errorf("cluster: got %q, want %q", p.Cluster, "nas")
	}
	if p.KeyURI == keyURIPlaceholder {
		t.Error("keyuri was left unexpanded")
	}
}

func TestResolveKeepsExplicitValues(t *testing.T) {
	p := newSetupParams("nas:6443")
	p.CAURL = "https://ca.example.com:9000"
	p.Context = "work"
	p.Cluster = "prod"
	p.KeyURI = "yubikey:slot-id=9a"
	if err := p.resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.CAURL != "https://ca.example.com:9000" || p.Context != "work" ||
		p.Cluster != "prod" || p.KeyURI != "yubikey:slot-id=9a" {
		t.Errorf("resolve overwrote an explicit value: %+v", p)
	}
}

func TestResolveRejectsAnUnparseableURL(t *testing.T) {
	p := newSetupParams("://")
	if err := p.resolve(); err == nil {
		t.Error("expected an error for an unparseable KUBEAPI_URL")
	}
}

func newSetupParams(url string) *params {
	return &params{
		Setup:      true,
		KubeAPIURL: url,
		CAURL:      caURLPlaceholder,
		KeyURI:     keyURIPlaceholder,
		Username:   "system:admin",
		Context:    hostnamePlaceholder,
		Cluster:    hostnamePlaceholder,
	}
}

// kubectl invokes the plugin with exactly the argv `k8sss setup` wrote into
// the kubeconfig: short options with the value attached, values containing
// colons, slashes and at-signs.
func TestParsesTheExecPluginArgv(t *testing.T) {
	argv := []string{
		"cert",
		"-ksshagentkms:tester@workstation",
		"-usystem:admin",
		"-chttps://nas:9000",
		"nas",
	}
	opts, err := docopt.ParseArgs(usage, argv, "")
	if err != nil {
		t.Fatalf("parsing %q: %v", argv, err)
	}
	var p params
	if err := opts.Bind(&p); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if err := p.resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !p.Cert {
		t.Error("the cert command was not selected")
	}
	if p.KeyURI != "sshagentkms:tester@workstation" {
		t.Errorf("keyuri: got %q", p.KeyURI)
	}
	if p.Username != "system:admin" {
		t.Errorf("username: got %q", p.Username)
	}
	if p.CAURL != "https://nas:9000" {
		t.Errorf("ca-url: got %q", p.CAURL)
	}
	if p.KubeAPIHostname != "nas" {
		t.Errorf("hostname: got %q", p.KubeAPIHostname)
	}
}

// The hostname and username become path elements under ~/.config/k8sss, and
// rm removes the directory they name.
func TestResolveRejectsPathsInNamesUsedAsDirectories(t *testing.T) {
	for _, tc := range []struct{ hostname, username string }{
		{"../../etc", "system:admin"},
		{"..", "system:admin"},
		{".", "system:admin"},
		{"a/b", "system:admin"},
		{"nas", "../../root"},
		{"nas", "a/b"},
	} {
		p := &params{
			KubeAPIHostname: tc.hostname,
			Username:        tc.username,
			CAURL:           caURLPlaceholder,
			KeyURI:          "sshagentkms:tester@workstation",
			Context:         hostnamePlaceholder,
			Cluster:         hostnamePlaceholder,
		}
		if err := p.resolve(); err == nil {
			t.Errorf("hostname %q username %q was accepted", tc.hostname, tc.username)
		}
	}
}

func TestResolveAcceptsOrdinaryNames(t *testing.T) {
	p := &params{
		KubeAPIHostname: "k8s.example.com",
		Username:        "system:admin",
		CAURL:           caURLPlaceholder,
		KeyURI:          "sshagentkms:tester@workstation",
		Context:         hostnamePlaceholder,
		Cluster:         hostnamePlaceholder,
	}
	if err := p.resolve(); err != nil {
		t.Errorf("resolve: %v", err)
	}
}
