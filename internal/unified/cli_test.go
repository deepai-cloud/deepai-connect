package unified

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/buildinfo"
)

func commandOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = stdout }()
	err = Run(context.Background(), args)
	b, readErr := os.ReadFile(f.Name())
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), err
}

func TestPrimaryCLIHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}, {"help"}} {
		out, err := commandOutput(t, args...)
		if err != nil || !strings.HasPrefix(out, "Usage: deepai-connect COMMAND") {
			t.Fatalf("primary help failed for %v: %v", args, err)
		}
		for _, command := range []string{"create --name", "enroll --role", "join --name", "resume", "publish --hostname", "/var/lib/deepai-connect"} {
			if !strings.Contains(out, command) {
				t.Fatalf("primary help omits %q", command)
			}
		}
		for _, obsolete := range []string{"Docker", "Headscale", "FRPC", "up --domain", "access --out"} {
			if strings.Contains(out, obsolete) {
				t.Fatalf("primary help advertises an unrelated service manager: %q", obsolete)
			}
		}
	}
	for _, arg := range []string{"version", "--version"} {
		out, err := commandOutput(t, arg)
		if err != nil || out != buildinfo.Version+"\n" {
			t.Fatalf("version failed: %q %v", out, err)
		}
	}
}

func TestPrimaryCLICommandHelpNeedsNoHostInstallation(t *testing.T) {
	for _, command := range []string{"create", "join", "resume", "inspect", "enroll", "publish", "route", "policy", "gateway", "egress", "agent", "agent-ready", "coordinator", "relay"} {
		t.Run(command, func(t *testing.T) {
			if err := Run(context.Background(), []string{command, "--help"}); err != nil {
				t.Fatalf("help attempted installation or runtime access: %v", err)
			}
		})
	}
}

func TestPrimaryCLIRejectsUnrelatedCommandsWithoutCreatingState(t *testing.T) {
	for _, command := range []string{"up", "status", "invite", "access", "unknown"} {
		t.Run(command, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			err := Run(context.Background(), []string{command, "--dir", dir})
			if err == nil || !strings.Contains(err.Error(), "unknown command") {
				t.Fatalf("unrecognized command reached a runtime: %v", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("unrecognized command created private state")
			}
		})
	}
}
