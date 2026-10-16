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
	for _, command := range []string{"setup", "status", "doctor", "nodes", "containers", "logs", "kubectl", "kubeconfig", "tunnel"} {
		if err := run(context.Background(), []string{command, "--help"}, "darwin"); err != nil {
			t.Errorf("%s --help: %v", command, err)
		}
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("help wrote configuration: %v", err)
	}
}
