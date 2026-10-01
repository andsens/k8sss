// Package k8sss implements the k8sss commands: establishing trust with a
// Kubernetes cluster and issuing client certificates from its Smallstep CA.
package k8sss

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Params is the command line, bound by docopt in main. It lives here rather
// than beside the usage string because docopt binds a single struct covering
// every option, and the commands need to read it.
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

// Config is what a command runs on: the command line with the on-disk
// locations for this cluster worked out. The layout matches what the shell
// implementation used, so existing setups keep working.
type Config struct {
	Params

	configDir   string
	dir         string
	serverCACrt string
	clientCACrt string
	userCrt     string
	userKey     string
	kubeconfig  string
}

// Config works out where everything lives for the cluster named on the command
// line. Call it once the placeholder defaults have been expanded.
func (p *Params) Config() (*Config, error) {
	// The hostname and the username become path elements below, and Remove
	// deletes the directory the hostname names, so neither may point
	// somewhere else.
	for name, value := range map[string]string{
		"KUBEAPI_HOSTNAME": p.KubeAPIHostname,
		"--username":       p.Username,
	} {
		if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
			return nil, fmt.Errorf("%s '%s' may not be a path", name, value)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("Unable to determine the home directory: %w", err)
	}
	config := &Config{Params: *p}
	config.configDir = filepath.Join(home, ".config", "k8sss")
	config.dir = filepath.Join(config.configDir, p.KubeAPIHostname)
	config.serverCACrt = filepath.Join(config.dir, "server-ca.crt")
	config.clientCACrt = filepath.Join(config.dir, "client-ca.crt")
	config.userCrt = filepath.Join(config.dir, p.Username+".crt")
	config.userKey = filepath.Join(config.dir, p.Username+".key")
	config.kubeconfig = filepath.Join(home, ".kube", "config.yaml")
	return config, nil
}

// ExecArgs is the argument list `k8sss setup` writes into the kubeconfig for
// kubectl to invoke the credential plugin with. It is the other half of the
// usage string in main.
func ExecArgs(p *Params) []string {
	return []string{
		"cert",
		"-k" + p.KeyURI,
		"-u" + p.Username,
		"-c" + p.CAURL,
		p.KubeAPIHostname,
	}
}
