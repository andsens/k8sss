package main

import (
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/andsens/k8sss/internal/k8sss"
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
			config, err := setupParams(tc.arg).resolve()
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if config.KubeAPIHostname != tc.hostname {
				t.Errorf("hostname: got %q, want %q", config.KubeAPIHostname, tc.hostname)
			}
			if config.KubeAPIURL != tc.url {
				t.Errorf("url: got %q, want %q", config.KubeAPIURL, tc.url)
			}
		})
	}
}

func TestResolveExpandsThePlaceholderDefaults(t *testing.T) {
	config, err := setupParams("nas:6443").resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := "https://nas:9000"; config.CAURL != want {
		t.Errorf("ca-url: got %q, want %q", config.CAURL, want)
	}
	if config.Context != "nas" || config.Cluster != "nas" {
		t.Errorf("context/cluster: got %q/%q, want nas/nas", config.Context, config.Cluster)
	}
	if config.KeyURI == keyURIPlaceholder {
		t.Error("keyuri was left unexpanded")
	}
}

func TestResolveKeepsExplicitValues(t *testing.T) {
	params := setupParams("nas:6443")
	params.CAURL = "https://ca.example.com:9000"
	params.Context = "work"
	params.Cluster = "prod"
	params.KeyURI = "yubikey:slot-id=9a"
	config, err := params.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if config.CAURL != "https://ca.example.com:9000" || config.Context != "work" ||
		config.Cluster != "prod" || config.KeyURI != "yubikey:slot-id=9a" {
		t.Errorf("resolve overwrote an explicit value: %+v", config)
	}
}

func TestResolveRejectsAnUnparseableURL(t *testing.T) {
	if _, err := setupParams("://").resolve(); err == nil {
		t.Error("expected an error for an unparseable KUBEAPI_URL")
	}
}

// The plugin invocation `k8sss setup` stores has to parse back into the same
// values. Asserting the argument shape where it is built and where it is
// parsed would not catch the two drifting together.
func TestExecArgsParseBackToTheSameConfig(t *testing.T) {
	config := &k8sss.Config{
		KubeAPIHostname: "nas",
		CAURL:           "https://nas:9000",
		KeyURI:          "sshagentkms:tester@workstation",
		Username:        "system:admin",
	}
	parsed, err := parseArgv(k8sss.ExecArgs(config))
	if err != nil {
		t.Fatalf("k8sss cannot parse the arguments it writes: %v", err)
	}
	if parsed.KeyURI != config.KeyURI || parsed.Username != config.Username ||
		parsed.CAURL != config.CAURL || parsed.KubeAPIHostname != config.KubeAPIHostname {
		t.Errorf("round trip lost something:\n got %+v\nwant %+v", parsed, config)
	}
}

// kubectl invokes the plugin with short options whose values are attached and
// contain colons, slashes and at-signs.
func TestUsageParsesTheExecPluginArgv(t *testing.T) {
	argv := []string{
		"cert",
		"-ksshagentkms:tester@workstation",
		"-usystem:admin",
		"-chttps://nas:9000",
		"nas",
	}
	params := Params{}
	opts, err := docopt.ParseArgs(usage, argv, "")
	if err != nil {
		t.Fatalf("parsing %q: %v", argv, err)
	}
	if err := opts.Bind(&params); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if !params.Cert {
		t.Error("the cert command was not selected")
	}
	if params.KeyURI != "sshagentkms:tester@workstation" {
		t.Errorf("keyuri: got %q", params.KeyURI)
	}
	if params.Username != "system:admin" {
		t.Errorf("username: got %q", params.Username)
	}
}

// parseArgv runs an argument list through the same parse and resolve main does.
func parseArgv(argv []string) (*k8sss.Config, error) {
	opts, err := docopt.ParseArgs(usage, argv, "")
	if err != nil {
		return nil, err
	}
	params := Params{}
	if err := opts.Bind(&params); err != nil {
		return nil, err
	}
	return params.resolve()
}
