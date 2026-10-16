//go:build (linux || darwin) && (amd64 || arm64)

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMacHostCommandsDoNotCreateLinuxState(t *testing.T) {
	for _, command := range []string{"create", "join", "resume", "inspect", "agent", "gateway"} {
		t.Run(command, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			err := run(context.Background(), []string{command, "--dir", dir}, "darwin")
			if err == nil || !strings.Contains(err.Error(), "Linux host") {
				t.Fatalf("expected host guidance, got %v", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("host command touched state on macOS: %v", err)
			}
		})
	}
}

func TestMacHostCommandHelpStillAvailable(t *testing.T) {
	if err := run(context.Background(), []string{"create", "--help"}, "darwin"); err != nil {
		t.Fatal(err)
	}
}

func TestAdministrationHelpNeedsNoConfiguration(t *testing.T) {
	config := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("DEEPAI_CONNECT_CONFIG", config)
	for _, command := range []string{"setup", "status", "network", "doctor", "nodes", "containers", "logs", "kubectl", "kubeconfig", "tunnel"} {
		if err := run(context.Background(), []string{command, "--help"}, "darwin"); err != nil {
			t.Errorf("%s --help: %v", command, err)
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
	for _, command := range []string{"setup", "status", "network", "doctor", "containers", "logs", "kubectl", "create", "inspect", "version"} {
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
	for _, platform := range []string{"darwin", "linux"} {
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
