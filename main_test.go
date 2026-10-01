package main

import (
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/andsens/k8sss/internal/k8sss"
)

func setupParams(url string) *k8sss.Params {
	return &k8sss.Params{
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
			config, err := resolve(setupParams(tc.arg))
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
	config, err := resolve(setupParams("nas:6443"))
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
	config, err := resolve(params)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if config.CAURL != "https://ca.example.com:9000" || config.Context != "work" ||
		config.Cluster != "prod" || config.KeyURI != "yubikey:slot-id=9a" {
		t.Errorf("resolve overwrote an explicit value: %+v", config)
	}
}

func TestResolveRejectsAnUnparseableURL(t *testing.T) {
	if _, err := resolve(setupParams("://")); err == nil {
		t.Error("expected an error for an unparseable KUBEAPI_URL")
	}
}

// The plugin invocation `k8sss setup` stores has to parse back into the same
// values. Asserting the argument shape where it is built and where it is
// parsed would not catch the two drifting together.
func TestExecArgsParseBackToTheSameConfig(t *testing.T) {
	params := &k8sss.Params{
		KubeAPIHostname: "nas",
		CAURL:           "https://nas:9000",
		KeyURI:          "sshagentkms:tester@workstation",
		Username:        "system:admin",
	}
	parsed, err := parseArgv(k8sss.ExecArgs(params))
	if err != nil {
		t.Fatalf("k8sss cannot parse the arguments it writes: %v", err)
	}
	if parsed.KeyURI != params.KeyURI || parsed.Username != params.Username ||
		parsed.CAURL != params.CAURL || parsed.KubeAPIHostname != params.KubeAPIHostname {
		t.Errorf("round trip lost something:\n got %+v\nwant %+v", parsed.Params, params)
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
	config, err := parseArgv(argv)
	if err != nil {
		t.Fatalf("parsing %q: %v", argv, err)
	}
	if !config.Cert {
		t.Error("the cert command was not selected")
	}
	if config.KeyURI != "sshagentkms:tester@workstation" {
		t.Errorf("keyuri: got %q", config.KeyURI)
	}
	if config.Username != "system:admin" {
		t.Errorf("username: got %q", config.Username)
	}
	if config.KubeAPIHostname != "nas" {
		t.Errorf("hostname: got %q", config.KubeAPIHostname)
	}
}

// parseArgv runs an argument list through the same parse and resolve main does.
func parseArgv(argv []string) (*k8sss.Config, error) {
	opts, err := docopt.ParseArgs(usage, argv, "")
	if err != nil {
		return nil, err
	}
	params := k8sss.Params{}
	if err := opts.Bind(&params); err != nil {
		return nil, err
	}
	return resolve(&params)
}
