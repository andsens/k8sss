package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/andsens/k8sss/internal/k8sss"
)

func setupConfig(url string) *k8sss.Config {
	return &k8sss.Config{
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
			config := setupConfig(tc.arg)
			if err := resolve(config, true); err != nil {
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
	config := setupConfig("nas:6443")
	if err := resolve(config, true); err != nil {
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
	config := setupConfig("nas:6443")
	config.CAURL = "https://ca.example.com:9000"
	config.Context = "work"
	config.Cluster = "prod"
	config.KeyURI = "yubikey:slot-id=9a"
	if err := resolve(config, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if config.CAURL != "https://ca.example.com:9000" || config.Context != "work" ||
		config.Cluster != "prod" || config.KeyURI != "yubikey:slot-id=9a" {
		t.Errorf("resolve overwrote an explicit value: %+v", config)
	}
}

func TestResolveRejectsAnUnparseableURL(t *testing.T) {
	if err := resolve(setupConfig("://"), true); err == nil {
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
	params, config, err := parse(argv)
	if err != nil {
		t.Fatalf("parsing %q: %v", argv, err)
	}
	if !params.Cert {
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

// Every subcommand and option in the usage string has to land in a struct with
// a field for it, however the command line is written. A key routed to the
// wrong struct shows up here as a Bind error.
func TestSplitRoutesEveryKeyToAStructThatWantsIt(t *testing.T) {
	for _, argv := range [][]string{
		{"ls"},
		{"rm", "nas"},
		{"rm", "--context", "work", "nas"},
		{"cert", "-ksshagentkms:a@b", "-usystem:admin", "-chttps://nas:9000", "nas"},
		{"setup", "nas:6443"},
		{"setup", "--ca-url", "https://nas:9000", "-ksshagentkms:a@b", "-uadmin",
			"--context", "work", "--cluster", "prod", "nas:6443"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if _, _, err := parse(argv); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

// parse runs an argument list through the same split and pair of Binds main
// does.
func parse(argv []string) (*Params, *k8sss.Config, error) {
	opts, err := docopt.ParseArgs(usage, argv, "")
	if err != nil {
		return nil, nil, err
	}
	commands, options := split(opts)
	params := Params{}
	if err := commands.Bind(&params); err != nil {
		return nil, nil, fmt.Errorf("binding subcommands: %w", err)
	}
	config := k8sss.Config{}
	if err := options.Bind(&config); err != nil {
		return nil, nil, fmt.Errorf("binding options: %w", err)
	}
	return &params, &config, nil
}

// parseArgv parses and resolves, the way main does end to end.
func parseArgv(argv []string) (*k8sss.Config, error) {
	params, config, err := parse(argv)
	if err != nil {
		return nil, err
	}
	return config, resolve(config, params.Setup)
}
