package main

import "testing"

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
