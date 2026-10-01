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
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/andsens/k8sss/internal/k8sss"
)

type Params struct {
	Setup bool `docopt:"setup"`
	Rm    bool `docopt:"rm"`
	Ls    bool `docopt:"ls"`
	Cert  bool `docopt:"cert"`
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

// The defaults above are placeholders rather than values docopt can supply, so
// they are compared against verbatim and expanded once the hostname is known.
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
	commands, options := split(parser)
	params := Params{}
	err = commands.Bind(&params)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	config := k8sss.Config{}
	err = options.Bind(&config)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	err = resolve(&config, params.Setup)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	ctx := context.Background()
	if params.Setup {
		err = k8sss.Setup(ctx, &config)
	}
	if params.Rm {
		err = k8sss.Remove(&config)
	}
	if params.Ls {
		err = k8sss.List(&config)
	}
	if params.Cert {
		err = k8sss.Cert(ctx, &config)
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// split sorts the parsed keys into the two structs that want them. docopt
// binds a struct that accounts for every key it was given, and skips embedded
// fields, so one struct cannot cover the subcommands alone and embedding does
// not help. docopt's own naming tells the keys apart: options start with a
// dash and arguments are upper case, while subcommands are plain lower-case
// words. A key that lands in the wrong one fails loudly at Bind.
func split(opts docopt.Opts) (commands, options docopt.Opts) {
	commands, options = docopt.Opts{}, docopt.Opts{}
	for key, value := range opts {
		if strings.HasPrefix(key, "-") || key == strings.ToUpper(key) {
			options[key] = value
		} else {
			commands[key] = value
		}
	}
	return commands, options
}

// kubeAPIURL splits the KUBEAPI_URL argument into a hostname and a normalised
// URL, defaulting to https when no scheme was given.
var kubeAPIURL = regexp.MustCompile(`^(https?://)?([^:/]+)(:[^:/]+)?`)

// resolve expands the placeholder defaults and, for setup, derives the
// hostname from the URL that was passed.
func resolve(config *k8sss.Config, setup bool) error {
	if setup {
		match := kubeAPIURL.FindStringSubmatch(config.KubeAPIURL)
		if match == nil {
			return fmt.Errorf("Unable to parse KUBEAPI_URL '%s'", config.KubeAPIURL)
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
			return fmt.Errorf("Unable to determine the current user: %w", err)
		}
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("Unable to determine the hostname: %w", err)
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
	return nil
}
