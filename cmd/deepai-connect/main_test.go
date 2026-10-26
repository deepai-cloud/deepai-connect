//go:build (linux || darwin || windows) && (amd64 || arm64)

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/unified"
)

func TestDesktopHostCommandsDoNotCreateLinuxState(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		for _, command := range unified.Commands {
			if command == "version" || command == "--version" || unified.PortableCommand([]string{command}) {
				continue
			}
			t.Run(goos+"/"+command, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "state")
				err := run(context.Background(), []string{command, "--dir", dir}, goos)
				if err == nil || !strings.Contains(err.Error(), "Linux host") {
					t.Fatalf("expected host guidance, got %v", err)
				}
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatalf("host command touched state on %s: %v", goos, err)
				}
			})
		}
	}
}

func TestCloudCommandsReachManifestValidationOnDesktop(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		for _, command := range []string{"plan", "apply", "enroll"} {
			args := []string{command, "-f", filepath.Join(t.TempDir(), "missing.yaml")}
			if command == "enroll" {
				args = append(args, "--node=worker", "--out="+filepath.Join(t.TempDir(), "worker.invite"))
			}
			err := run(context.Background(), args, goos)
			if err == nil || !strings.Contains(err.Error(), "open cloud manifest") {
				t.Fatalf("%s %s did not reach the portable path: %v", goos, command, err)
			}
		}
	}
}

func TestDesktopHostCommandHelpAndVersionStillAvailable(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		for _, args := range [][]string{{"create", "--help"}, {"help", "create"}, {"version"}, {"--version"}} {
			if err := run(context.Background(), args, goos); err != nil {
				t.Fatalf("%s %v: %v", goos, args, err)
			}
		}
	}
}

func TestAdministrationHelpNeedsNoConfiguration(t *testing.T) {
	config := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("DEEPAI_CONNECT_CONFIG", config)
	for _, goos := range []string{"darwin", "windows"} {
		for _, command := range []string{"setup", "status", "network", "vm", "doctor", "nodes", "containers", "logs", "kubectl", "kubeconfig", "tunnel"} {
			if err := run(context.Background(), []string{command, "--help"}, goos); err != nil {
				t.Errorf("%s %s --help: %v", goos, command, err)
			}
		}
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("help wrote configuration: %v", err)
	}
}

func runOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	err = run(context.Background(), args, "darwin")
	b, readErr := os.ReadFile(f.Name())
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), err
}

func TestStartIsOfflineAndCompact(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("DEEPAI_CONNECT_CONFIG", p)
	if err := os.WriteFile(p, []byte(`{"hub":"root@offline.invalid","stateDir":"/var/lib/deepai-connect","overlayIP":"100.96.0.1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runOutput(t)
	if err != nil || !strings.Contains(out, "Saved hub: root@offline.invalid (not checked)") || !strings.Contains(out, "status") || strings.Contains(out, "create --name") {
		t.Fatalf("start should show short offline navigation: %q, %v", out, err)
	}
	out, err = runOutput(t, "--help")
	if err != nil || !strings.Contains(out, "Everyday") || !strings.Contains(out, "Advanced") || !strings.Contains(out, "create --name") {
		t.Fatalf("full help should show all command groups: %q, %v", out, err)
	}
	if err := os.WriteFile(p, []byte("broken config"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = runOutput(t)
	if err != nil || !strings.Contains(out, "Saved hub unavailable: invalid client configuration") {
		t.Fatalf("start hid a broken configuration: %q, %v", out, err)
	}
}

func TestHelpCommandMatchesFlag(t *testing.T) {
	t.Setenv("DEEPAI_CONNECT_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	for _, command := range []string{"setup", "status", "network", "nodes", "vm", "doctor", "containers", "logs", "kubectl", "create", "inspect", "version"} {
		flagHelp, err := runOutput(t, command, "--help")
		if err != nil {
			t.Fatalf("%s --help: %v", command, err)
		}
		commandHelp, err := runOutput(t, "help", command)
		if err != nil || commandHelp != flagHelp || !strings.Contains(commandHelp, "Usage") {
			t.Fatalf("help %s differs from --help: %q vs %q, %v", command, commandHelp, flagHelp, err)
		}
	}
}

func TestUnknownCommandsAreNotLinuxHostErrors(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		err := run(context.Background(), []string{"stats"}, platform)
		if err == nil || !strings.Contains(err.Error(), `did you mean "status"`) || strings.Contains(err.Error(), "Linux host") {
			t.Fatalf("typo should offer navigation on %s: %v", platform, err)
		}
		err = run(context.Background(), []string{"unrecognized"}, platform)
		if err == nil || !strings.Contains(err.Error(), "unknown command") || strings.Contains(err.Error(), "Linux host") {
			t.Fatalf("unknown command should offer help on %s: %v", platform, err)
		}
	}
}

func TestLifecycleHelpAndUnsupportedHostAreNonMutating(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing-client.json")
	t.Setenv("DEEPAI_CONNECT_CONFIG", p)
	for _, args := range [][]string{
		{"host", "--help"}, {"host", "start", "--help"},
		{"host", "startup", "--help"}, {"host", "startup", "enable", "--help"},
		{"vm", "start", "--help"}, {"vm", "startup", "--help"},
	} {
		out, err := runOutput(t, args...)
		if err != nil || !strings.Contains(out, "Usage:") {
			t.Fatalf("%v help unavailable: %s, %v", args, out, err)
		}
	}
	dir := filepath.Join(t.TempDir(), "host-state")
	out, err := runOutput(t, "host", "start", "--dir", dir, "--json")
	var report struct {
		SchemaVersion int    `json:"schemaVersion"`
		Platform      string `json:"platform"`
		Error         struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err == nil || json.Unmarshal([]byte(out), &report) != nil || report.SchemaVersion != 1 || report.Platform != "darwin" || report.Error.Code != "host_required" {
		t.Fatalf("unsupported host result is not structured: %q, %v", out, err)
	}
	for _, path := range []string{p, dir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("read/help command created %s: %v", path, err)
		}
	}
}
