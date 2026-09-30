// k8sss issues short-lived Kubernetes client certificates from a Smallstep CA,
// authenticating with a key held by an SSH agent, YubiKey, TPM or any other
// backend addressable by a Smallstep KMS URI.
package main

import (
	"log/slog"
	"os"

	docopt "github.com/docopt/docopt-go"

	"github.com/andsens/k8sss/internal/k8sss"
)

func main() {
	// $LOGLEVEL takes the level names slog itself parses: DEBUG, INFO, WARN
	// and ERROR, optionally with an offset such as DEBUG+2. The variable is
	// shared with tools that use other names for their levels, so a value
	// slog cannot read leaves the default level in place rather than failing.
	if name := os.Getenv("LOGLEVEL"); name != "" {
		var level slog.Level
		if err := level.UnmarshalText([]byte(name)); err != nil {
			slog.Warn("Ignoring $LOGLEVEL", "error", err)
		} else {
			slog.SetLogLoggerLevel(level)
		}
	}

	opts, err := docopt.ParseArgs(k8sss.Usage, os.Args[1:], "")
	if err != nil {
		slog.Error("Unable to parse arguments", "error", err)
		os.Exit(1)
	}
	var params k8sss.Params
	if err := opts.Bind(&params); err != nil {
		slog.Error("Unable to bind arguments", "error", err)
		os.Exit(1)
	}

	if err := run(&params); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(params *k8sss.Params) error {
	if err := params.Resolve(); err != nil {
		return err
	}
	switch {
	case params.Ls:
		return k8sss.List(params)
	case params.Rm:
		return k8sss.Remove(params)
	case params.Setup:
		return k8sss.Setup(params)
	case params.Cert:
		return k8sss.Cert(params)
	}
	return nil
}
