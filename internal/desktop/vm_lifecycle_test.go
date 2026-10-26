package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func lifecycleBackend(t *testing.T, name, state string) (*[]string, *string) {
	t.Helper()
	desktopTestConfig(t)
	calls := []string{}
	desktopMockRunner(t, func(ctx context.Context, command string, args []string, _ io.Reader, out, _ io.Writer) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded process")
		}
		call := command + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if command != "multipass" {
			t.Fatalf("unexpected command: %s", call)
		}
		switch strings.Join(args, " ") {
		case "list --format json":
			if state == "" {
				fmt.Fprint(out, `{"list":[]}`)
			} else {
				fmt.Fprintf(out, `{"list":[{"name":%q,"state":%q}]}`, name, state)
			}
		case "get client.primary-name":
			fmt.Fprint(out, "primary\n")
		case "start --timeout 300 " + name:
			state = "Running"
		case "stop " + name:
			state = "Stopped"
		default:
			t.Fatalf("unexpected call: %s", call)
		}
		return nil
	})
	return &calls, &state
}

func TestVMLifecycleExistingNamedWorker(t *testing.T) {
	for _, tc := range []struct {
		action, before, after string
		calls                 int
	}{
		{"start", "Stopped", "Running", 4}, {"start", "Suspended", "Running", 4}, {"start", "Running", "Running", 1},
		{"stop", "Running", "Stopped", 3}, {"stop", "Stopped", "Stopped", 1}, {"status", "Unknown", "Unknown", 1},
	} {
		t.Run(tc.action+"-"+tc.before, func(t *testing.T) {
			calls, _ := lifecycleBackend(t, "my-worker-42", tc.before)
			var out bytes.Buffer
			if err := vmLifecycleCommand(context.Background(), []string{tc.action, "--name", "my-worker-42", "--json"}, "windows", &out); err != nil {
				t.Fatal(err)
			}
			var r vmLifecycleReport
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if r.SchemaVersion != 1 || r.State != tc.after || r.Changed != (tc.before != tc.after) || len(*calls) != tc.calls {
				t.Fatalf("report=%+v calls=%v", r, *calls)
			}
		})
	}
}

func TestVMLifecycleSavedNameAndIdentityPreserved(t *testing.T) {
	_, _ = lifecycleBackend(t, "worker-1", "Stopped")
	cfg := Config{Hub: "root@hub.example", StateDir: defaultStateDir, OverlayIP: "100.96.0.1", VM: "worker-1"}
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	before, _ := os.ReadFile(p)
	var out bytes.Buffer
	if err := runVMTo(context.Background(), []string{"start", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("start changed saved identity/configuration")
	}
}

func TestVMLifecycleRejectsMissingUnsafeOrPrimaryVM(t *testing.T) {
	for _, tc := range []struct{ action, name, state string }{
		{"start", "worker-1", ""}, {"stop", "worker-1", ""}, {"start", "worker-1", "Unknown"},
		{"stop", "worker-1", "Suspended"}, {"start", "primary", "Stopped"}, {"start", "worker-1", "Deleted"},
	} {
		t.Run(tc.action+tc.name+tc.state, func(t *testing.T) {
			calls, _ := lifecycleBackend(t, tc.name, tc.state)
			var out bytes.Buffer
			err := vmLifecycleCommand(context.Background(), []string{tc.action, "--name", tc.name, "--json"}, "darwin", &out)
			if err == nil {
				t.Fatal("expected error")
			}
			var report map[string]any
			if json.Unmarshal(out.Bytes(), &report) != nil || report["error"] != err.Error() {
				t.Fatalf("missing JSON error: %s", out.String())
			}
			for _, call := range *calls {
				if strings.Contains(call, " start ") || strings.Contains(call, " stop ") {
					t.Fatalf("unsafe mutation: %v", calls)
				}
			}
		})
	}
}

func TestVMLifecycleInvalidFlagsNamesAndStartupPlatformAreStructured(t *testing.T) {
	for _, args := range [][]string{
		{"start", "--invalid", "--json"}, {"start", "--name", "a b", "--json"}, {"start", "--name", "--all", "--json"},
		{"startup", "enable", "--name", "worker-1", "--json"}, {"startup", "uninstall", "--name", "worker-1", "--json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			desktopMockRunner(t, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
				t.Fatal("unexpected process")
				return nil
			})
			var out bytes.Buffer
			err := vmLifecycleCommand(context.Background(), args, "windows", &out)
			if err == nil || !json.Valid(out.Bytes()) {
				t.Fatalf("err=%v output=%s", err, out.String())
			}
		})
	}
}

func TestVMLifecycleMutationFailuresAndPostconditions(t *testing.T) {
	for _, mode := range []string{"command", "post-state", "post-read"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			desktopMockRunner(t, func(_ context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
				switch args[0] {
				case "list":
					reads++
					if reads > 1 && mode == "post-read" {
						return errors.New("daemon disappeared")
					}
					fmt.Fprint(out, `{"list":[{"name":"worker-1","state":"Stopped"}]}`)
				case "get":
					fmt.Fprint(out, "primary\n")
				case "start":
					if mode == "command" {
						return errors.New("timeout")
					}
				default:
					t.Fatalf("unexpected: %v", args)
				}
				return nil
			})
			var out bytes.Buffer
			err := vmLifecycleCommand(context.Background(), []string{"start", "--name", "worker-1", "--json"}, "darwin", &out)
			if err == nil || !json.Valid(out.Bytes()) {
				t.Fatalf("err=%v output=%s", err, out.String())
			}
		})
	}
}

func startupFixture(t *testing.T) (vmStartupEnv, *[]string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("macOS launchd filesystem fixtures use Unix paths; Windows unsupported behavior is tested separately")
	}
	env := vmStartupEnv{home: t.TempDir(), executable: "/Users/person/Applications/Connect & tools/deepai-connect", uid: 501}
	oldEnv, oldLook := vmStartupEnvironment, vmStartupLookPath
	vmStartupEnvironment = func() (vmStartupEnv, error) { return env, nil }
	vmStartupLookPath = func(string) (string, error) { return "/Applications/Multipass tools/bin/multipass", nil }
	t.Cleanup(func() { vmStartupEnvironment = oldEnv; vmStartupLookPath = oldLook })
	calls := []string{}
	desktopMockRunner(t, func(ctx context.Context, command string, args []string, _ io.Reader, out, _ io.Writer) error {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Minute {
			t.Fatal("unbounded startup process")
		}
		call := command + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "multipass list --format json":
			fmt.Fprint(out, `{"list":[{"name":"worker-42","state":"Running"}]}`)
		case "multipass get client.primary-name":
			fmt.Fprint(out, "primary\n")
		case "launchctl print-disabled gui/501":
			fmt.Fprint(out, "disabled services = {\n}\n")
		default:
			t.Fatalf("unexpected process: %s", call)
		}
		return nil
	})
	return env, &calls
}

func TestVMStartupEnableStatusDisableNextLoginOnly(t *testing.T) {
	env, calls := startupFixture(t)
	r, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Enabled || !r.Configured || !r.Changed || r.Trigger != "login" {
		t.Fatalf("%+v", r)
	}
	data, err := os.ReadFile(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedVMStartup(data, "worker-42") || !bytes.Contains(data, []byte("Connect &amp; tools")) || bytes.Contains(data, []byte("KeepAlive")) {
		t.Fatalf("invalid plist: %s", data)
	}
	want := renderVMStartup("worker-42", env.executable, "/Applications/Multipass tools/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	if !bytes.Equal(data, want) {
		t.Fatal("plist does not preserve exact executable/name/path")
	}
	r, err = configureVMStartup(context.Background(), "worker-42", "enable", "darwin")
	if err != nil || r.Changed {
		t.Fatalf("not idempotent: %+v %v", r, err)
	}
	r, err = configureVMStartup(context.Background(), "worker-42", "status", "darwin")
	if err != nil || !r.Enabled || r.Changed {
		t.Fatalf("status: %+v %v", r, err)
	}
	before := len(*calls)
	r, err = configureVMStartup(context.Background(), "worker-42", "disable", "darwin")
	if err != nil || r.Enabled || r.Configured || !r.Changed {
		t.Fatalf("disable: %+v %v", r, err)
	}
	if len(*calls) != before {
		t.Fatal("disable ran a process")
	}
	r, err = configureVMStartup(context.Background(), "worker-42", "disable", "darwin")
	if err != nil || r.Changed {
		t.Fatalf("second disable: %+v %v", r, err)
	}
	for _, call := range *calls {
		if strings.Contains(call, " bootstrap ") || strings.Contains(call, " start ") || strings.Contains(call, " stop ") || strings.Contains(call, "bootout") {
			t.Fatalf("startup changed runtime: %v", *calls)
		}
	}
}

func TestVMStartupDoesNotClobberEditedOrSymlinkedFiles(t *testing.T) {
	for _, mode := range []string{"foreign", "edited", "symlink", "parent-link"} {
		t.Run(mode, func(t *testing.T) {
			env, calls := startupFixture(t)
			dir := filepath.Join(env.home, "Library", "LaunchAgents")
			p := filepath.Join(dir, "cloud.deepai.connect.vm.worker-42.plist")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("user-owned")
			if mode == "edited" {
				data = append(renderVMStartup("worker-42", env.executable, "/bin"), []byte("<!-- user -->")...)
			}
			if mode == "symlink" {
				target := filepath.Join(env.home, "keep")
				os.WriteFile(target, data, 0600)
				if err := os.Symlink(target, p); err != nil {
					t.Skip(err)
				}
			} else if mode == "parent-link" {
				os.Remove(dir)
				target := filepath.Join(env.home, "keep-dir")
				os.Mkdir(target, 0700)
				if err := os.Symlink(target, dir); err != nil {
					t.Skip(err)
				}
			} else {
				os.WriteFile(p, data, 0600)
			}
			for _, action := range []string{"enable", "disable", "status"} {
				if _, err := configureVMStartup(context.Background(), "worker-42", action, "darwin"); err == nil {
					t.Fatalf("%s accepted %s", action, mode)
				}
			}
			if len(*calls) != 0 {
				t.Fatalf("unexpected commands: %v", *calls)
			}
		})
	}
}

func TestVMStartupOverrideAndEnableFailureRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			env, _ := startupFixture(t)
			base := runProcess
			enables := 0
			runProcess = func(ctx context.Context, command string, args []string, in io.Reader, out, stderr io.Writer) error {
				if command == "launchctl" {
					if args[0] == "print-disabled" {
						fmt.Fprint(out, "disabled services = {\n \"cloud.deepai.connect.vm.worker-42\" => true\n}\n")
						return nil
					}
					if !reflect.DeepEqual(args, []string{"enable", "gui/501/cloud.deepai.connect.vm.worker-42"}) {
						t.Fatalf("wrong enable: %v", args)
					}
					enables++
					if fail {
						return errors.New("enable denied")
					}
					return nil
				}
				return base(ctx, command, args, in, out, stderr)
			}
			r, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin")
			p := filepath.Join(env.home, "Library", "LaunchAgents", "cloud.deepai.connect.vm.worker-42.plist")
			if fail {
				if err == nil {
					t.Fatal("expected failure")
				}
				if _, stat := os.Stat(p); !errors.Is(stat, os.ErrNotExist) {
					t.Fatal("failed enable left startup file")
				}
			} else if err != nil || !r.Enabled {
				t.Fatalf("%+v %v", r, err)
			}
			if enables != 1 {
				t.Fatal("did not clear disabled override exactly once")
			}
		})
	}
}

func TestVMStartupRejectsTemporaryExecutableAndChangedLocation(t *testing.T) {
	env, _ := startupFixture(t)
	stable := env
	for _, root := range []string{os.TempDir(), "/tmp", "/var/tmp"} {
		temp, err := filepath.EvalSymlinks(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		env.executable = filepath.Join(temp, "go-build123", "deepai-connect")
		vmStartupEnvironment = func() (vmStartupEnv, error) { return env, nil }
		if _, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin"); err == nil {
			t.Fatalf("accepted temporary executable under %s (resolved %s)", root, temp)
		}
	}
	vmStartupEnvironment = func() (vmStartupEnv, error) { return stable, nil }
	r, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(r.Path)
	stable.executable = "/new/path/deepai-connect"
	if _, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin"); err == nil {
		t.Fatal("overwrote changed executable")
	}
	after, _ := os.ReadFile(r.Path)
	if !bytes.Equal(before, after) {
		t.Fatal("changed existing entry")
	}
	if _, err := configureVMStartup(context.Background(), "worker-42", "disable", "darwin"); err != nil {
		t.Fatal("cannot remove old installed path:", err)
	}
}

func TestVMStartupStatusDisabledAndMalformedOverrides(t *testing.T) {
	for _, override := range []string{"true", "false", "unknown"} {
		t.Run(override, func(t *testing.T) {
			_, _ = startupFixture(t)
			r, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin")
			if err != nil {
				t.Fatal(err)
			}
			desktopMockRunner(t, func(_ context.Context, command string, args []string, _ io.Reader, out, _ io.Writer) error {
				if command != "launchctl" || args[0] != "print-disabled" {
					t.Fatalf("unexpected %s %v", command, args)
				}
				fmt.Fprintf(out, "disabled services = {\n \"cloud.deepai.connect.vm.worker-42\" => %s\n}\n", override)
				return nil
			})
			r, err = configureVMStartup(context.Background(), "worker-42", "status", "darwin")
			if override == "unknown" {
				if err == nil {
					t.Fatal("unknown override reported enabled")
				}
				return
			}
			if err != nil || r.Enabled != (override == "false") {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestVMStartupDisablePreservesGatewayAndVMConfiguration(t *testing.T) {
	env, _ := startupFixture(t)
	r, err := configureVMStartup(context.Background(), "worker-42", "enable", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(filepath.Dir(r.Path), "cloud.deepai.inference.node.plist")
	sentinel := []byte("separate gateway-owned startup")
	if err = os.WriteFile(gateway, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(env.home, ".config", "deepai-connect", "client.json")
	if err = os.WriteFile(identity, []byte("existing configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	vmStartupLookPath = func(string) (string, error) { return "", errors.New("Multipass removed") }
	if _, err = configureVMStartup(context.Background(), "worker-42", "disable", "darwin"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(gateway)
	if !bytes.Equal(data, sentinel) {
		t.Fatal("touched gateway")
	}
	data, _ = os.ReadFile(identity)
	if string(data) != "existing configuration" {
		t.Fatal("touched identity")
	}
}

// Validate the generated file with Apple's parser without loading a job.
func TestVMStartupPlistSyntaxOnMac(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Apple plist parser is macOS-only")
	}
	path := filepath.Join(t.TempDir(), "startup.plist")
	data := renderVMStartup("worker-42", "/Users/person/Connect & tools/deepai-connect", "/Applications/Multipass tools/bin:/usr/bin:/bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", "--", path).CombinedOutput(); err != nil {
		t.Fatalf("invalid launchd plist: %v %s", err, out)
	}
}

// Forward check of the packaged skill's read-only request: inspect the selected
// worker and its next-login preference without starting it or writing settings.
func TestVMLifecycleSkillInspectStartupDoesNotStartOrWrite(t *testing.T) {
	env, _ := startupFixture(t)
	cfg := desktopTestConfig(t)
	cfg.VM = "worker-42"
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.home, "Library", "LaunchAgents", "cloud.deepai.connect.vm.worker-42.plist")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := renderVMStartup(cfg.VM, env.executable, "/usr/local/bin:/usr/bin:/bin")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	desktopMockRunner(t, func(_ context.Context, command string, args []string, _ io.Reader, out, _ io.Writer) error {
		call := command + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "multipass list --format json":
			fmt.Fprint(out, `{"list":[{"name":"worker-42","state":"Stopped"}]}`)
		case "launchctl print-disabled gui/501":
			fmt.Fprint(out, "disabled services = {\n}\n")
		default:
			t.Fatalf("inspection made an unexpected call: %s", call)
		}
		return nil
	})
	var stateOut, startupOut bytes.Buffer
	if err := vmLifecycleCommand(context.Background(), []string{"status", "--json"}, "darwin", &stateOut); err != nil {
		t.Fatal(err)
	}
	if err := vmLifecycleCommand(context.Background(), []string{"startup", "status", "--json"}, "darwin", &startupOut); err != nil {
		t.Fatal(err)
	}
	var state vmLifecycleReport
	var startup vmStartupReport
	if err := json.Unmarshal(stateOut.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(startupOut.Bytes(), &startup); err != nil {
		t.Fatal(err)
	}
	if state.State != "Stopped" || state.Changed || !startup.Enabled || startup.Changed || startup.Trigger != "login" {
		t.Fatalf("state=%+v startup=%+v", state, startup)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("inspection rewrote startup file")
	}
	if _, err := os.Stat(filepath.Join(env.home, ".config", "deepai-connect", "vm-startup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created mutation lock/state")
	}
	if len(calls) != 2 {
		t.Fatal(calls)
	}
}
