// k8sss issues short-lived Kubernetes client certificates from a Smallstep CA,
// authenticating with a key held by an SSH agent, YubiKey, TPM or any other
// backend addressable by a Smallstep KMS URI.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"regexp"

	"github.com/docopt/docopt-go"

	"github.com/andsens/k8sss/internal/k8sss"
)

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

// The defaults in the usage string are placeholders rather than values docopt
// can supply, so they are compared against verbatim and expanded once the
// hostname is known.
const (
	caURLPlaceholder    = "https://$KUBEAPI_HOSTNAME:9000"
	keyURIPlaceholder   = "sshagentkms:$USER@$HOST"
	hostnamePlaceholder = "$KUBEAPI_HOSTNAME"
)

func main() {
	slog.SetDefault(slog.Default())
	switch os.Getenv("LOGLEVEL") {
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "verbose":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "info":
		slog.SetLogLoggerLevel(slog.LevelInfo)
	case "warning":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
		slog.SetLogLoggerLevel(slog.LevelError)
	}
	parser, err := docopt.ParseDoc(usage)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	params := Params{}
	err = parser.Bind(&params)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	config, err := params.resolve()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	ctx := context.Background()
	if params.Setup {
		err = k8sss.Setup(ctx, config)
	}
	if params.Rm {
		err = k8sss.Remove(config)
	}
	if params.Ls {
		err = k8sss.List(config)
	}
	if params.Cert {
		err = k8sss.Cert(ctx, config)
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// kubeAPIURL splits the KUBEAPI_URL argument into a hostname and a normalised
// URL, defaulting to https when no scheme was given.
var kubeAPIURL = regexp.MustCompile(`^(https?://)?([^:/]+)(:[^:/]+)?`)

// resolve expands the placeholder defaults and, for setup, derives the
// hostname from the URL that was passed.
func (p *Params) resolve() (*k8sss.Config, error) {
	config := &k8sss.Config{
		KubeAPIURL:      p.KubeAPIURL,
		KubeAPIHostname: p.KubeAPIHostname,
		CAURL:           p.CAURL,
		KeyURI:          p.KeyURI,
		Username:        p.Username,
		Context:         p.Context,
		Cluster:         p.Cluster,
	}
	if p.Setup {
		match := kubeAPIURL.FindStringSubmatch(p.KubeAPIURL)
		if match == nil {
			return nil, fmt.Errorf("Unable to parse KUBEAPI_URL '%s'", p.KubeAPIURL)
		}
		scheme, host, port := match[1], match[2], match[3]
		if scheme == "" {
			scheme = "https://"
		}
		config.KubeAPIHostname = host
		config.KubeAPIURL = scheme + host + port
	}
	if config.KeyURI == keyURIPlaceholder {
		usr, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("Unable to determine the current user: %w", err)
		}
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("Unable to determine the hostname: %w", err)
		}
		config.KeyURI = "sshagentkms:" + usr.Username + "@" + host
	}
	if config.Context == hostnamePlaceholder {
		config.Context = config.KubeAPIHostname
	}
	if config.Cluster == hostnamePlaceholder {
		config.Cluster = config.KubeAPIHostname
	}
	if config.CAURL == caURLPlaceholder {
		config.CAURL = "https://" + config.KubeAPIHostname + ":9000"
	}
	return config, nil
}
