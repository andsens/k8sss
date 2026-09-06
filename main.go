// k8sss issues short-lived Kubernetes client certificates from a Smallstep CA,
// authenticating with a key held by an SSH agent, YubiKey, TPM or any other
// backend addressable by a Smallstep KMS URI.
package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	docopt "github.com/docopt/docopt-go"
)

const usage = `k8sss - Issue Kubernetes client certificates via Smallstep
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

// The defaults above are placeholders rather than values docopt can supply, so
// they are compared against verbatim and expanded once the hostname is known.
const (
	caURLPlaceholder    = "https://$KUBEAPI_HOSTNAME:9000"
	keyURIPlaceholder   = "sshagentkms:$USER@$HOST"
	hostnamePlaceholder = "$KUBEAPI_HOSTNAME"
)

type params struct {
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

// paths holds the on-disk locations for one cluster. The layout matches what
// the shell implementation used, so existing setups keep working.
type paths struct {
	dir         string
	serverCACrt string
	clientCACrt string
	userCrt     string
	userKey     string
	kubeconfig  string
}

func main() {
	setupLogging()

	opts, err := docopt.ParseArgs(usage, os.Args[1:], "")
	if err != nil {
		fatal(fmt.Errorf("Unable to parse arguments: %w", err))
	}
	var p params
	if err := opts.Bind(&p); err != nil {
		fatal(fmt.Errorf("Unable to bind arguments: %w", err))
	}
	if err := p.resolve(); err != nil {
		fatal(err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fatal(fmt.Errorf("Unable to determine home directory: %w", err))
	}
	configDir := filepath.Join(home, ".config", "k8sss")
	pth := paths{
		dir:        filepath.Join(configDir, p.KubeAPIHostname),
		kubeconfig: filepath.Join(home, ".kube", "config.yaml"),
	}
	pth.serverCACrt = filepath.Join(pth.dir, "server-ca.crt")
	pth.clientCACrt = filepath.Join(pth.dir, "client-ca.crt")
	pth.userCrt = filepath.Join(pth.dir, p.Username+".crt")
	pth.userKey = filepath.Join(pth.dir, p.Username+".key")

	switch {
	case p.Ls:
		err = listClusters(configDir)
	case p.Rm:
		err = removeCluster(&p, &pth, configDir)
	case p.Setup:
		err = setupCluster(&p, &pth)
	case p.Cert:
		err = issueCert(&p, &pth)
	}
	if err != nil {
		fatal(err)
	}
}

// kubeAPIURL splits the KUBEAPI_URL argument into a hostname and a normalised
// URL, defaulting to https when no scheme was given.
var kubeAPIURL = regexp.MustCompile(`^(https?://)?([^:/]+)(:[^:/]+)?`)

// resolve expands the placeholder defaults and, for setup, derives the
// hostname from the URL the user passed.
func (p *params) resolve() error {
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
			return fmt.Errorf("Unable to determine current user: %w", err)
		}
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("Unable to determine hostname: %w", err)
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
	return nil
}
