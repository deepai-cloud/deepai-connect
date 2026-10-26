package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupPreferenceDefaultsAndRejectsMalformedState(t *testing.T) {
	dir := t.TempDir()
	if enabled, err := StartupEnabled(dir); err != nil || !enabled {
		t.Fatalf("%t %v", enabled, err)
	}
	for _, enabled := range []bool{false, true} {
		if err := SetStartupEnabled(dir, enabled); err != nil {
			t.Fatal(err)
		}
		if got, err := StartupEnabled(dir); err != nil || got != enabled {
			t.Fatalf("%t %v", got, err)
		}
	}
	for _, data := range []string{`{}`, `{"version":1}`, `{"version":2,"enabled":false}`, `{"version":1,"enabled":false,"extra":true}`, `{"version":1,"enabled":false} {}`} {
		if err := os.WriteFile(filepath.Join(dir, "host-startup.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := StartupEnabled(dir); err == nil {
			t.Fatal("accepted malformed preference", data)
		}
	}
}

func TestInstallHonorsManualBootPreference(t *testing.T) {
	c := config(t)
	f := &fakeRunner{}
	m := newManager(t, c, f)
	if err := SetStartupEnabled(filepath.Dir(m.Config.AgentStateDir), false); err != nil {
		t.Fatal(err)
	}
	f.run = func(_ []byte, name string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if name == m.Config.K3sBinary && joined == "--version" {
			return []byte("k3s version " + K3sVersion), nil
		}
		if strings.Contains(joined, "get --raw=/readyz") {
			return []byte("ok"), nil
		}
		if strings.Contains(joined, "get node ") {
			return readyNode(m.Config.OverlayIP), nil
		}
		return nil, nil
	}
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	var disabled, started bool
	for _, call := range f.calls {
		if call.command != "systemctl" {
			continue
		}
		switch strings.Join(call.args, " ") {
		case "disable " + UnitName:
			disabled = true
		case "start --no-block " + UnitName:
			started = true
		}
		if len(call.args) > 0 && call.args[0] == "enable" {
			t.Fatal("manual boot preference was re-enabled", call.args)
		}
	}
	if !disabled || !started {
		t.Fatalf("disabled=%t started=%t", disabled, started)
	}
}

func TestInstallRejectsUnreadableBootPreferenceBeforeMutation(t *testing.T) {
	c := config(t)
	f := &fakeRunner{}
	m := newManager(t, c, f)
	dir := filepath.Dir(m.Config.AgentStateDir)
	if err := os.MkdirAll(filepath.Join(dir, "host-startup.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.Install(context.Background()); err == nil {
		t.Fatal("invalid preference accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid preference invoked commands", f.calls)
	}
	if _, err := os.Stat(filepath.Join(m.Config.DataDir, "cluster.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed cluster state")
	}
}
