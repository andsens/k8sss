// Package k8sss implements the k8sss commands: establishing trust with a
// Kubernetes cluster and issuing client certificates from its Smallstep CA.
package k8sss

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is a command's input, with the placeholder defaults from the usage
// string already expanded.
type Config struct {
	KubeAPIURL      string
	KubeAPIHostname string
	CAURL           string
	KeyURI          string
	Username        string
	Context         string
	Cluster         string
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

func (c *Config) paths() (*paths, error) {
	// The hostname and the username become path elements below, and Remove
	// deletes the directory the hostname names, so neither may point
	// somewhere else.
	for name, value := range map[string]string{
		"KUBEAPI_HOSTNAME": c.KubeAPIHostname,
		"--username":       c.Username,
	} {
		if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
			return nil, fmt.Errorf("%s '%s' may not be a path", name, value)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("Unable to determine the home directory: %w", err)
	}
	configDir := filepath.Join(home, ".config", "k8sss")
	dir := filepath.Join(configDir, c.KubeAPIHostname)
	return &paths{
		configDir:   configDir,
		dir:         dir,
		serverCACrt: filepath.Join(dir, "server-ca.crt"),
		clientCACrt: filepath.Join(dir, "client-ca.crt"),
		userCrt:     filepath.Join(dir, c.Username+".crt"),
		userKey:     filepath.Join(dir, c.Username+".key"),
		kubeconfig:  filepath.Join(home, ".kube", "config.yaml"),
	}, nil
}

// ExecArgs is the argument list `k8sss setup` writes into the kubeconfig for
// kubectl to invoke the credential plugin with. It is the other half of the
// usage string in main.
func ExecArgs(c *Config) []string {
	return []string{
		"cert",
		"-k" + c.KeyURI,
		"-u" + c.Username,
		"-c" + c.CAURL,
		c.KubeAPIHostname,
	}
}
