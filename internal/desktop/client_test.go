package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReportCommandFlagErrorsPreserveOutputContract(t *testing.T) {
	for _, command := range []string{"network", "nodes"} {
		for _, tc := range []struct {
			args       []string
			json, help bool
		}{
			{[]string{"--invalid", "--json"}, true, false},
			{[]string{"--json", "--invalid", "--json=false"}, false, false},
			{[]string{"--invalid", "--json=false", "--json=true"}, true, false},
			{[]string{"--invalid", "--", "--json"}, false, false},
			{[]string{"--json", "--help"}, false, true},
		} {
			t.Run(command+"/"+strings.Join(tc.args, " "), func(t *testing.T) {
				var out bytes.Buffer
				var err error
				if command == "network" {
					err = networkCommand(context.Background(), tc.args, "linux", &out)
				} else {
					err = nodesCommand(context.Background(), tc.args, &out)
				}
				if err == nil || errors.Is(err, flag.ErrHelp) != tc.help {
					t.Fatalf("unexpected error: %v", err)
				}
				if tc.json {
					var envelope struct {
						SchemaVersion int
						Error         string
					}
					if json.Unmarshal(out.Bytes(), &envelope) != nil || envelope.SchemaVersion != 1 || envelope.Error != err.Error() {
						t.Fatalf("invalid failure envelope: %s", out.String())
					}
				} else if out.Len() != 0 {
					t.Fatalf("unexpected structured output: %s", out.String())
				}
			})
		}
	}
}

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

func captureOutput(t *testing.T, run func() error) (string, string, error) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = out, stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	err = run()
	output, readErr := os.ReadFile(out.Name())
	if readErr != nil {
		t.Fatal(readErr)
	}
	errors, readErr := os.ReadFile(stderr.Name())
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), string(errors), err
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
	// Commands execute on the Linux hub, even when the client runs on Windows.
	// Use a POSIX shell when available to verify the remote quoting boundary.
	t.Run("remote-shell", func(t *testing.T) {
		if _, err := exec.LookPath("sh"); err != nil {
			t.Skip("POSIX shell is not installed on this client")
		}
		got, err := exec.Command("sh", "-c", args[len(args)-1]).Output()
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.Join(values, "\x00") + "\x00"; string(got) != want {
			t.Fatalf("argument injection or corruption: %q, want %q", got, want)
		}
	})
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
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0600) {
		t.Fatalf("configuration is not private: %v, %v", fi, err)
	}
}

func TestClientConfigRejectsSymlinks(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	link := filepath.Join(t.TempDir(), "linked-client.json")
	if err := os.Symlink(p, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Setenv("DEEPAI_CONNECT_CONFIG", link)
	if _, err := loadConfig(); err == nil {
		t.Fatal("read linked client configuration")
	}
	if err := saveConfig(cfg); err == nil {
		t.Fatal("overwrote linked client configuration")
	}
}

func TestSetupSavesVerifiedAccessWhenClusterOrVMFails(t *testing.T) {
	cfg := desktopTestConfig(t)
	desktopMockRunner(t, func(_ context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
		if name == "ssh" && strings.Contains(args[len(args)-1], "'inspect'") {
			io.WriteString(out, testInspection(time.Now()))
			return nil
		}
		return errors.New("unavailable")
	})
	out, warnings, err := captureOutput(t, func() error {
		return setup(context.Background(), []string{"--hub", cfg.Hub, "--vm", "worker"})
	})
	if err != nil || !strings.Contains(out, "deepai-connect doctor") || !strings.Contains(warnings, "Kubernetes API") || !strings.Contains(warnings, "local VM") {
		t.Fatalf("verified access should survive optional health failures: %q %q %v", out, warnings, err)
	}
	saved, err := loadConfig()
	if err != nil || saved.Hub != cfg.Hub || saved.VM != "worker" || saved.OverlayIP != cfg.OverlayIP {
		t.Fatalf("verified access not saved: %+v, %v", saved, err)
	}
}

func TestSetupRejectsInvalidIdentityWithoutOverwriting(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	for _, inspection := range []string{"not an installed hub", strings.ReplaceAll(testInspection(time.Now()), "100.96.0.1", "192.0.2.1")} {
		desktopMockRunner(t, func(_ context.Context, _ string, _ []string, _ io.Reader, out, _ io.Writer) error {
			io.WriteString(out, inspection)
			return nil
		})
		if err := setup(context.Background(), []string{"--hub", "root@replacement.example"}); err == nil {
			t.Fatal("invalid hub identity accepted")
		}
		if saved, err := loadConfig(); err != nil || saved != cfg {
			t.Fatalf("invalid identity overwrote config: %+v, %v", saved, err)
		}
	}
}

func TestContainersKeepExplicitOutputPure(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	var command string
	var failure error
	desktopMockRunner(t, func(_ context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
		command = args[len(args)-1]
		io.WriteString(out, "kubectl output\n")
		return failure
	})
	for _, flags := range [][]string{{"-o", "json"}, {"--output=yaml"}, {"-ojson"}, {"--no-headers"}, {"--watch"}} {
		out, _, err := captureOutput(t, func() error { return Run(context.Background(), append([]string{"containers"}, flags...)) })
		if err != nil || out != "kubectl output\n" {
			t.Fatalf("explicit output %v was decorated: %q, %v", flags, out, err)
		}
		if hasOutputFormat(flags) && strings.Contains(command, "'-o' 'wide'") {
			t.Fatalf("explicit format was overridden: %s", command)
		}
	}
	out, _, err := captureOutput(t, func() error { return Run(context.Background(), []string{"containers"}) })
	if err != nil || !strings.Contains(out, "Workloads (Kubernetes pods)") || !strings.Contains(out, "Next: deepai-connect logs <POD> -n <NAMESPACE>") {
		t.Fatalf("human workload navigation missing: %q, %v", out, err)
	}
	failure = errors.New("SSH failed")
	out, _, err = captureOutput(t, func() error { return Run(context.Background(), []string{"containers"}) })
	if err == nil || strings.Contains(out, "Next:") {
		t.Fatalf("failed listing offered a success footer: %q, %v", out, err)
	}
}

func TestHelpWithArgumentsDoesNotContactHub(t *testing.T) {
	desktopTestConfig(t)
	desktopMockRunner(t, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("help attempted to contact hub")
		return nil
	})
	for _, args := range [][]string{{"logs", "example", "-n", "app", "--help"}, {"containers", "--namespace", "app", "--help"}, {"network", "--json", "--help"}, {"kubectl", "--help"}} {
		out, _, err := captureOutput(t, func() error { return Run(context.Background(), args) })
		if err != nil || !strings.Contains(out, "Usage: deepai-connect "+args[0]) {
			t.Fatalf("help %v failed: %q, %v", args, out, err)
		}
	}
	if requestsHelp([]string{"exec", "pod", "--", "sh", "--help"}) {
		t.Fatal("container command help was consumed by the CLI")
	}
}

func TestKubectlCommandHelpIsForwarded(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	var command string
	desktopMockRunner(t, func(_ context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
		command = args[len(args)-1]
		io.WriteString(out, "kubectl exec help\n")
		return nil
	})
	out, _, err := captureOutput(t, func() error { return Run(context.Background(), []string{"kubectl", "exec", "--help"}) })
	if err != nil || out != "kubectl exec help\n" || !strings.Contains(command, "'exec' '--help'") {
		t.Fatalf("kubectl command help was not forwarded: %q %q %v", command, out, err)
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
