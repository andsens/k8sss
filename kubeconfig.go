package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// writeKubeconfig adds (or updates) the cluster, user and context for this
// Kubernetes API server, leaving every other entry in the file alone.
func writeKubeconfig(p *params, pth *paths, serverCA []byte) error {
	config, err := loadKubeconfig(pth.kubeconfig)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Unable to determine the path to k8sss: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}

	cluster, ok := config.Clusters[p.Cluster]
	if !ok {
		cluster = api.NewCluster()
	}
	cluster.Server = p.KubeAPIURL
	cluster.CertificateAuthorityData = serverCA
	cluster.CertificateAuthority = ""
	config.Clusters[p.Cluster] = cluster
	slog.Info(fmt.Sprintf("Cluster %q set", p.Cluster))

	userName := p.Username + "@" + p.Cluster
	authInfo, ok := config.AuthInfos[userName]
	if !ok {
		authInfo = api.NewAuthInfo()
	}
	authInfo.Exec = &api.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Command:    executable,
		Args: []string{
			"cert",
			"-k" + p.KeyURI,
			"-u" + p.Username,
			"-c" + p.CAURL,
			p.KubeAPIHostname,
		},
	}
	config.AuthInfos[userName] = authInfo
	slog.Info(fmt.Sprintf("User %q set", userName))

	context, ok := config.Contexts[p.Context]
	if !ok {
		context = api.NewContext()
	}
	context.Cluster = p.Cluster
	context.AuthInfo = userName
	config.Contexts[p.Context] = context
	slog.Info(fmt.Sprintf("Context %q set", p.Context))

	if err := os.MkdirAll(filepath.Dir(pth.kubeconfig), 0o755); err != nil {
		return fmt.Errorf("Unable to create %s: %w", filepath.Dir(pth.kubeconfig), err)
	}
	if err := clientcmd.WriteToFile(*config, pth.kubeconfig); err != nil {
		return fmt.Errorf("Unable to write %s: %w", pth.kubeconfig, err)
	}
	return nil
}

func loadKubeconfig(path string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(path)
	if os.IsNotExist(err) {
		return api.NewConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("Unable to read %s: %w", path, err)
	}
	return config, nil
}

// listClusters names every cluster that has been set up, which is one
// directory per Kubernetes API server hostname.
func listClusters(configDir string) error {
	entries, err := os.ReadDir(configDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Unable to read %s: %w", configDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			fmt.Println(entry.Name())
		}
	}
	return nil
}

// removeCluster drops the stored certificates along with the context and the
// cluster and user it refers to.
func removeCluster(p *params, pth *paths, configDir string) error {
	if p.KubeAPIHostname == "" {
		return fmt.Errorf("KUBEAPI_HOSTNAME must not be empty")
	}
	if err := os.RemoveAll(pth.dir); err != nil {
		return fmt.Errorf("Unable to remove %s: %w", pth.dir, err)
	}
	config, err := loadKubeconfig(pth.kubeconfig)
	if err != nil {
		return err
	}
	context, ok := config.Contexts[p.Context]
	if !ok {
		slog.Warn(fmt.Sprintf("Unable to find the context '%s' in your kubeconfig. You will have to remove the user, cluster, and context manually", p.Context))
		return nil
	}
	delete(config.Clusters, context.Cluster)
	delete(config.AuthInfos, context.AuthInfo)
	delete(config.Contexts, p.Context)
	if config.CurrentContext == p.Context {
		config.CurrentContext = ""
	}
	if err := clientcmd.WriteToFile(*config, pth.kubeconfig); err != nil {
		return fmt.Errorf("Unable to write %s: %w", pth.kubeconfig, err)
	}
	return nil
}
