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
			params := setupParams(tc.arg)
			if err := resolve(params); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if params.KubeAPIHostname != tc.hostname {
				t.Errorf("hostname: got %q, want %q", params.KubeAPIHostname, tc.hostname)
			}
			if params.KubeAPIURL != tc.url {
				t.Errorf("url: got %q, want %q", params.KubeAPIURL, tc.url)
			}
		})
	}
}

func TestResolveExpandsThePlaceholderDefaults(t *testing.T) {
	params := setupParams("nas:6443")
	if err := resolve(params); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := "https://nas:9000"; params.CAURL != want {
		t.Errorf("ca-url: got %q, want %q", params.CAURL, want)
	}
	if params.Context != "nas" || params.Cluster != "nas" {
		t.Errorf("context/cluster: got %q/%q, want nas/nas", params.Context, params.Cluster)
	}
	if params.KeyURI == keyURIPlaceholder {
		t.Error("keyuri was left unexpanded")
	}
}

func TestResolveKeepsExplicitValues(t *testing.T) {
	params := setupParams("nas:6443")
	params.CAURL = "https://ca.example.com:9000"
	params.Context = "work"
	params.Cluster = "prod"
	params.KeyURI = "yubikey:slot-id=9a"
	if err := resolve(params); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if params.CAURL != "https://ca.example.com:9000" || params.Context != "work" ||
		params.Cluster != "prod" || params.KeyURI != "yubikey:slot-id=9a" {
		t.Errorf("resolve overwrote an explicit value: %+v", params)
	}
}

func TestResolveRejectsAnUnparseableURL(t *testing.T) {
	if err := resolve(setupParams("://")); err == nil {
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
		t.Errorf("round trip lost something:\n got %+v\nwant %+v", parsed, params)
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
	params := k8sss.Params{}
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
func parseArgv(argv []string) (*k8sss.Params, error) {
	opts, err := docopt.ParseArgs(usage, argv, "")
	if err != nil {
		return nil, err
	}
	params := k8sss.Params{}
	if err := opts.Bind(&params); err != nil {
		return nil, err
	}
	return &params, resolve(&params)
}
