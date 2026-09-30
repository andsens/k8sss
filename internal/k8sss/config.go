// Package k8sss implements the k8sss commands: establishing trust with a
// Kubernetes cluster and issuing client certificates from its Smallstep CA.
package k8sss

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

// Usage is the command line contract, and the source docopt parses the
// arguments against.
const Usage = `k8sss - Issue Kubernetes client certificates via Smallstep
Usage:
  k8sss setup [--ca-url URL -k KN -u UN --context NAME --cluster NAME] KUBEAPI_URL
  k8sss rm [--context NAME] KUBEAPI_HOSTNAME
  k8sss ls
  k8sss cert [--ca-url URL -k KN -u UN] KUBEAPI_HOSTNAME

Options:
  -c --ca-url URL   URL to the CA [default: https://$KUBEAPI_HOSTNAME:9000]
  -k --keyuri URI   Smallstep key URI used for authentication
                    [default: sshagentkms:$USER@$HOST]
  -u --username UN  K8S username to authenticate as [default: system:admin]
  --context NAME    Name of the context add/remove [default: $KUBEAPI_HOSTNAME]
  --cluster NAME    Name of the cluster add [default: $KUBEAPI_HOSTNAME]
`

// The defaults in the usage string are placeholders rather than values docopt
// can supply, so they are compared against verbatim and expanded once the
// hostname is known.
const (
	caURLPlaceholder    = "https://$KUBEAPI_HOSTNAME:9000"
	keyURIPlaceholder   = "sshagentkms:$USER@$HOST"
	hostnamePlaceholder = "$KUBEAPI_HOSTNAME"
)

// Params is the parsed command line.
type Params struct {
	Setup bool `docopt:"setup"`
	Rm    bool `docopt:"rm"`
	Ls    bool `docopt:"ls"`
	Cert  bool `docopt:"cert"`

	KubeAPIURL      string `docopt:"KUBEAPI_URL"`
	KubeAPIHostname string `docopt:"KUBEAPI_HOSTNAME"`

	CAURL    string `docopt:"--ca-url"`
	KeyURI   string `docopt:"--keyuri"`
	Username string `docopt:"--username"`
	Context  string `docopt:"--context"`
	Cluster  string `docopt:"--cluster"`
}

// kubeAPIURL splits the KUBEAPI_URL argument into a hostname and a normalised
// URL, defaulting to https when no scheme was given.
var kubeAPIURL = regexp.MustCompile(`^(https?://)?([^:/]+)(:[^:/]+)?`)

// Resolve expands the placeholder defaults and, for setup, derives the
// hostname from the URL that was passed.
func (p *Params) Resolve() error {
	if p.Setup {
		match := kubeAPIURL.FindStringSubmatch(p.KubeAPIURL)
		if match == nil {
			return fmt.Errorf("Unable to parse KUBEAPI_URL '%s'", p.KubeAPIURL)
		}
		scheme, host, port := match[1], match[2], match[3]
		if scheme == "" {
			scheme = "https://"
		}
		p.KubeAPIHostname = host
		p.KubeAPIURL = scheme + host + port
	}
	if p.KeyURI == keyURIPlaceholder {
		usr, err := user.Current()
		if err != nil {
			return fmt.Errorf("Unable to determine the current user: %w", err)
		}
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("Unable to determine the hostname: %w", err)
		}
		p.KeyURI = "sshagentkms:" + usr.Username + "@" + host
	}
	if p.Context == hostnamePlaceholder {
		p.Context = p.KubeAPIHostname
	}
	if p.Cluster == hostnamePlaceholder {
		p.Cluster = p.KubeAPIHostname
	}
	if p.CAURL == caURLPlaceholder {
		p.CAURL = "https://" + p.KubeAPIHostname + ":9000"
	}
	// Both of these become path elements under ~/.config/k8sss, and rm removes
	// the directory the hostname names, so neither may point elsewhere.
	if err := checkPathElement("KUBEAPI_HOSTNAME", p.KubeAPIHostname); err != nil {
		return err
	}
	return checkPathElement("--username", p.Username)
}

func checkPathElement(name, value string) error {
	if value == "" {
		return nil
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%s '%s' may not be a path", name, value)
	}
	return nil
}

// paths are the on-disk locations for one cluster. The layout matches what the
// shell implementation used, so existing setups keep working.
type paths struct {
	configDir   string
	dir         string
	serverCACrt string
	clientCACrt string
	userCrt     string
	userKey     string
	kubeconfig  string
}

func (p *Params) paths() (*paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("Unable to determine the home directory: %w", err)
	}
	configDir := filepath.Join(home, ".config", "k8sss")
	dir := filepath.Join(configDir, p.KubeAPIHostname)
	return &paths{
		configDir:   configDir,
		dir:         dir,
		serverCACrt: filepath.Join(dir, "server-ca.crt"),
		clientCACrt: filepath.Join(dir, "client-ca.crt"),
		userCrt:     filepath.Join(dir, p.Username+".crt"),
		userKey:     filepath.Join(dir, p.Username+".key"),
		kubeconfig:  filepath.Join(home, ".kube", "config.yaml"),
	}, nil
}
