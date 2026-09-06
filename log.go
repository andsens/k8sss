package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"
)

// The bash implementation logged through records.sh, which prefixes every line
// with the program name and colours warnings and errors when stderr is a
// terminal. cliHandler reproduces that output so the tool looks unchanged.
const (
	levelVerbose = slog.LevelDebug + 2
	programName  = "k8sss"
)

// records.sh orders its levels debug < verbose < info < warning < error <
// silent and reads the active one from $LOGLEVEL.
var logLevelNames = map[string]slog.Level{
	"debug":   slog.LevelDebug,
	"verbose": levelVerbose,
	"info":    slog.LevelInfo,
	"warning": slog.LevelWarn,
	"error":   slog.LevelError,
	"silent":  slog.LevelError + 4,
}

type cliHandler struct {
	out   io.Writer
	level slog.Level
	tty   bool
	attrs []slog.Attr
}

func (h *cliHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *cliHandler) Handle(_ context.Context, rec slog.Record) error {
	msg := rec.Message
	// Attributes are only used to carry the output of subprocesses and other
	// detail into debug lines, so append them rather than formatting a table.
	for _, attr := range h.attrs {
		msg += fmt.Sprintf(" %s=%v", attr.Key, attr.Value)
	}
	rec.Attrs(func(attr slog.Attr) bool {
		msg += fmt.Sprintf(" %s=%v", attr.Key, attr.Value)
		return true
	})
	line := programName + ": " + msg
	if h.tty {
		switch {
		case rec.Level == slog.LevelWarn:
			line = "\033[0;33m" + line + "\033[0m"
		case rec.Level >= slog.LevelError:
			line = "\033[0;31m" + line + "\033[0m"
		}
	}
	_, err := fmt.Fprintln(h.out, line)
	return err
}

func (h *cliHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

// Groups would only show up as noise in single-line CLI output.
func (h *cliHandler) WithGroup(string) slog.Handler { return h }

func setupLogging() {
	level := slog.LevelInfo
	if name := os.Getenv("LOGLEVEL"); name != "" {
		if parsed, ok := logLevelNames[strings.ToLower(name)]; ok {
			level = parsed
		}
	}
	slog.SetDefault(slog.New(&cliHandler{
		out:   os.Stderr,
		level: level,
		tty:   term.IsTerminal(int(os.Stderr.Fd())),
	}))
}

// fatal reports an unrecoverable error the way records.sh' fatal did: log it
// and exit non-zero.
func fatal(err error) {
	slog.Error(err.Error())
	os.Exit(1)
}
