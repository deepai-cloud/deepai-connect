package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func desktopTestConfig(t *testing.T) Config {
	t.Helper()
	t.Setenv("DEEPAI_CONNECT_CONFIG", filepath.Join(t.TempDir(), "client.json"))
	return Config{Hub: "root@hub.example", StateDir: defaultStateDir, OverlayIP: "100.96.0.1"}
}

func desktopMockRunner(t *testing.T, runner func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error) {
	t.Helper()
	old := runProcess
	runProcess = runner
	t.Cleanup(func() { runProcess = old })
}

func testInspection(now time.Time) string {
	return fmt.Sprintf("hub test: phase=ready address=100.96.0.1 voter=true\noverlay ready=true peers=1 last-sync=%s cache-expires=%s\n", now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
}

func TestSSHArgumentQuoting(t *testing.T) {
	cfg := desktopTestConfig(t)
	values := []string{"a b", "'quoted'", "$(printf injected)", "x; printf injected", "`printf injected`", "", "-flag", "{.items[*].metadata.name}"}
	args, err := sshArgs(cfg, append([]string{"printf", "%s\\000"}, values...))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), "StrictHostKeyChecking=no") || !strings.Contains(strings.Join(args, " "), "BatchMode=yes") {
		t.Fatalf("unsafe SSH options: %v", args[:len(args)-1])
	}
	// Execute only printf through a real POSIX shell to verify the quoting boundary.
	got, err := exec.Command("sh", "-c", args[len(args)-1]).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(values, "\x00") + "\x00"; string(got) != want {
		t.Fatalf("argument injection or corruption: %q, want %q", got, want)
	}
	for _, invalid := range []string{"line\nbreak", "line\rbreak", "nul\x00byte"} {
		if _, err := sshArgs(cfg, []string{"echo", invalid}); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	for _, host := range []string{"-oProxyCommand=whoami", "root@host;whoami", "root@host other", "root@$(whoami)", "root@host\nother"} {
		cfg.Hub = host
		if _, err := sshArgs(cfg, []string{"true"}); err == nil {
			t.Fatalf("accepted dangerous host %q", host)
		}
	}
}

func TestSetupPreservesSavedConfigurationOnFailure(t *testing.T) {
	cfg := desktopTestConfig(t)
	cfg.StateDir, cfg.VM = "/srv/private-connect", "worker"
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	before, _ := os.ReadFile(p)
	desktopMockRunner(t, func(_ context.Context, _ string, _ []string, _ io.Reader, _, _ io.Writer) error {
		return exec.ErrNotFound
	})
	if err := setup(context.Background(), []string{"--hub", "root@replacement.example"}); err == nil {
		t.Fatal("setup unexpectedly succeeded without SSH")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("failed setup changed saved configuration")
	}
}

func TestSetupRetainsPreferencesAndPrivatePermissions(t *testing.T) {
	cfg := desktopTestConfig(t)
	cfg.StateDir, cfg.VM = "/srv/owner's connect", "worker"
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	desktopMockRunner(t, func(_ context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
		if name == "multipass" {
			io.WriteString(out, `{"info":{"worker":{"state":"Running"}}}`)
		} else if strings.Contains(args[len(args)-1], "'inspect'") {
			io.WriteString(out, testInspection(time.Now()))
		} else if strings.Contains(args[len(args)-1], "'--raw=/readyz'") {
			io.WriteString(out, "ok")
		} else {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return nil
	})
	if err := setup(context.Background(), []string{"--hub", cfg.Hub}); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig()
	if err != nil || got != cfg {
		t.Fatalf("configuration preferences lost: %+v, %v", got, err)
	}
	p, _ := configPath()
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("configuration is not private: %v, %v", fi, err)
	}
}

func TestForwardingKeepsStdinAndScope(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	var command string
	desktopMockRunner(t, func(_ context.Context, name string, args []string, in io.Reader, _, _ io.Writer) error {
		if name != "ssh" || in != os.Stdin {
			t.Fatalf("stdin not forwarded: %s %v", name, in)
		}
		command = args[len(args)-1]
		return nil
	})
	if err := Run(context.Background(), []string{"containers", "--namespace", "app"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(command, "'--all-namespaces'") || !strings.Contains(command, "'--namespace' 'app'") {
		t.Fatalf("namespace not preserved: %s", command)
	}
	if err := Run(context.Background(), []string{"containers"}); err != nil || !strings.Contains(command, "'--all-namespaces'") {
		t.Fatalf("default all-namespace listing missing: %s, %v", command, err)
	}
}

func TestCaptureDropsCredentialOutputOnFailure(t *testing.T) {
	cfg := desktopTestConfig(t)
	desktopMockRunner(t, func(_ context.Context, _ string, _ []string, _ io.Reader, out, stderr io.Writer) error {
		io.WriteString(out, "secret-client-key")
		io.WriteString(stderr, "secret-client-key")
		return errors.New("SSH failed")
	})
	data, err := captureKube(context.Background(), cfg, "config", "view", "--raw")
	if data != nil || err == nil || strings.Contains(err.Error(), "secret-client-key") {
		t.Fatalf("credential output leaked: %q, %v", data, err)
	}
}

func TestNamespaceFlags(t *testing.T) {
	for _, args := range [][]string{{"-n", "app"}, {"-napp"}, {"--namespace=app"}, {"-A=false"}, {"--all-namespaces=false"}} {
		if !hasNamespace(args) {
			t.Fatalf("did not recognize namespace choice %v", args)
		}
	}
	if hasNamespace([]string{"--no-headers"}) {
		t.Fatal("mistook --no-headers for namespace")
	}
}

func TestNonRootHubUsesNoninteractiveSudo(t *testing.T) {
	cfg := desktopTestConfig(t)
	cfg.Hub = "admin@hub.example"
	want := []string{"sudo", "-n", "--", "systemctl", "is-active"}
	if got := privileged(cfg, []string{"systemctl", "is-active"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestInteractiveKubeTTYSelection(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"exec", "-it", "pod", "--", "sh"}, true},
		{[]string{"-n", "app", "attach", "--tty", "pod"}, true},
		{[]string{"exec", "-ti", "pod"}, true},
		{[]string{"exec", "-t", "--tty=false", "pod"}, false},
		{[]string{"exec", "-i", "pod", "--", "sh", "-t"}, false},
		{[]string{"logs", "-f", "pod"}, false},
	} {
		if got := kubeTTY(tc.args, true); got != tc.want {
			t.Errorf("%v: tty=%t, want %t", tc.args, got, tc.want)
		}
		if kubeTTY(tc.args, false) {
			t.Errorf("%v allocated a PTY for nonterminal stdin", tc.args)
		}
	}
}
