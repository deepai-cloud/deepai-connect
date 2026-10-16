package unified

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
)

func TestAgentPreservesEnrolledSigningIdentity(t *testing.T) {
	for _, role := range []string{"worker", "hub"} {
		for _, phase := range []string{"network", "cluster", "ready"} {
			t.Run(role+"/"+phase, func(t *testing.T) {
				dir := t.TempDir()
				i := testInstallation(dir)
				i.Config.Role, i.Config.FirstHub, i.Phase = role, false, phase
				original, err := enrollment.Identity(dir)
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := agentEnrollmentIdentity(dir, i)
				if err != nil || !bytes.Equal(original, loaded) {
					t.Fatalf("agent changed enrollment identity: %v", err)
				}
				path := filepath.Join(dir, "enrollment.key")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if _, err := agentEnrollmentIdentity(dir, i); err == nil {
					t.Fatal("agent recreated missing enrolled identity")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("failed recovery wrote a replacement key")
				}
			})
		}
	}
}

func TestFirstHubCreatesSignerOnlyDuringBootstrap(t *testing.T) {
	dir := t.TempDir()
	i := testInstallation(dir)
	original, err := agentEnrollmentIdentity(dir, i)
	if err != nil {
		t.Fatal(err)
	}
	i.Phase = "ready"
	loaded, err := agentEnrollmentIdentity(dir, i)
	if err != nil || !bytes.Equal(original, loaded) {
		t.Fatalf("ready first hub changed identity: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "enrollment.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := agentEnrollmentIdentity(dir, i); err == nil {
		t.Fatal("ready first hub recreated its signer")
	}
}
