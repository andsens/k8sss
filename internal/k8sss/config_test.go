package k8sss

import (
	"testing"

	docopt "github.com/docopt/docopt-go"
)

func setupParams(url string) *Params {
	return &Params{
		Setup:      true,
		KubeAPIURL: url,
		CAURL:      caURLPlaceholder,
		KeyURI:     keyURIPlaceholder,
		Username:   "system:admin",
		Context:    hostnamePlaceholder,
		Cluster:    hostnamePlaceholder,
	}
}

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
			p := setupParams(tc.arg)
			if err := p.Resolve(); err != nil {
				t.Fatalf("Resolve: %v", err)
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
	p := setupParams("nas:6443")
	if err := p.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "https://nas:9000"; p.CAURL != want {
		t.Errorf("ca-url: got %q, want %q", p.CAURL, want)
	}
	if p.Context != "nas" || p.Cluster != "nas" {
		t.Errorf("context/cluster: got %q/%q, want nas/nas", p.Context, p.Cluster)
	}
	if p.KeyURI == keyURIPlaceholder {
		t.Error("keyuri was left unexpanded")
	}
}

func TestResolveKeepsExplicitValues(t *testing.T) {
	p := setupParams("nas:6443")
	p.CAURL = "https://ca.example.com:9000"
	p.Context = "work"
	p.Cluster = "prod"
	p.KeyURI = "yubikey:slot-id=9a"
	if err := p.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.CAURL != "https://ca.example.com:9000" || p.Context != "work" ||
		p.Cluster != "prod" || p.KeyURI != "yubikey:slot-id=9a" {
		t.Errorf("Resolve overwrote an explicit value: %+v", p)
	}
}

func TestResolveRejectsAnUnparseableURL(t *testing.T) {
	if err := setupParams("://").Resolve(); err == nil {
		t.Error("expected an error for an unparseable KUBEAPI_URL")
	}
}

// The hostname and username become path elements under ~/.config/k8sss, and
// Remove deletes the directory the hostname names.
func TestResolveRejectsPathsInNamesUsedAsDirectories(t *testing.T) {
	for _, tc := range []struct{ hostname, username string }{
		{"../../etc", "system:admin"},
		{"..", "system:admin"},
		{".", "system:admin"},
		{"a/b", "system:admin"},
		{"nas", "../../root"},
		{"nas", "a/b"},
	} {
		p := &Params{
			KubeAPIHostname: tc.hostname,
			Username:        tc.username,
			CAURL:           caURLPlaceholder,
			KeyURI:          "sshagentkms:tester@workstation",
			Context:         hostnamePlaceholder,
			Cluster:         hostnamePlaceholder,
		}
		if err := p.Resolve(); err == nil {
			t.Errorf("hostname %q username %q was accepted", tc.hostname, tc.username)
		}
	}
}

func TestResolveAcceptsOrdinaryNames(t *testing.T) {
	p := &Params{
		KubeAPIHostname: "k8s.example.com",
		Username:        "system:admin",
		CAURL:           caURLPlaceholder,
		KeyURI:          "sshagentkms:tester@workstation",
		Context:         hostnamePlaceholder,
		Cluster:         hostnamePlaceholder,
	}
	if err := p.Resolve(); err != nil {
		t.Errorf("Resolve: %v", err)
	}
}

// kubectl invokes the plugin with the argv `k8sss setup` wrote into the
// kubeconfig: short options with the value attached, and values containing
// colons, slashes and at-signs.
func TestUsageParsesTheExecPluginArgv(t *testing.T) {
	argv := []string{
		"cert",
		"-ksshagentkms:tester@workstation",
		"-usystem:admin",
		"-chttps://nas:9000",
		"nas",
	}
	p, err := parseArgv(argv)
	if err != nil {
		t.Fatalf("parsing %q: %v", argv, err)
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

// parseArgv runs an argument list through the same parse main does.
func parseArgv(argv []string) (*Params, error) {
	opts, err := docopt.ParseArgs(Usage, argv, "")
	if err != nil {
		return nil, err
	}
	var p Params
	if err := opts.Bind(&p); err != nil {
		return nil, err
	}
	if err := p.Resolve(); err != nil {
		return nil, err
	}
	return &p, nil
}
