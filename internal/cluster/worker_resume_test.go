package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

func pendingWorker(t *testing.T, f *fakeRunner) *Manager {
	t.Helper()
	c := config(t)
	c.Name, c.Role, c.FirstHub, c.Voter = "worker-one", "worker", false, false
	c.OverlayIP, c.ServerURL = "100.64.0.2", "https://100.64.0.1:6443"
	c.JoinToken = "K10" + strings.Repeat("a", 64) + "::abcdef.1111111111111111"
	m := newManager(t, c, f)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFile(filepath.Join(m.Config.SystemdDir, UnitName), []byte(m.Unit()), false); err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFile(filepath.Join(m.Config.DataDir, "join-token"), []byte(m.Config.JoinToken+"\n"), false); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExpiredWorkerTokenReloadSurvivesInterruptedRestart(t *testing.T) {
	ctx := context.Background()
	f := &fakeRunner{}
	old := pendingWorker(t, f)
	c := old.Config
	c.JoinToken = "K10" + strings.Repeat("a", 64) + "::abcdef.2222222222222222"
	restarts, accepted := 0, false
	f.run = func(_ []byte, cmd string, args []string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch {
		case command == "--version":
			return []byte(K3sVersion), nil
		case strings.Contains(command, "get node"):
			if !accepted {
				return nil, errors.New("expired bootstrap credential: node not registered")
			}
			return readyNode(c.OverlayIP), nil
		case strings.Contains(command, "label node"):
			t.Fatal("worker attempted to assign an administrator-protected placement label")
		case cmd == "systemctl" && strings.HasPrefix(command, "restart "):
			restarts++
			saved, err := Load(c.DataDir, f)
			if err != nil || saved.Config.JoinToken != c.JoinToken || !saved.restartPending || saved.Joined {
				t.Fatal("reload was not durably journaled before restarting Kubernetes")
			}
			token, err := os.ReadFile(filepath.Join(c.DataDir, "join-token"))
			if err != nil || strings.TrimSpace(string(token)) != c.JoinToken {
				t.Fatal("K3s restarted without the refreshed credential")
			}
			if restarts == 1 {
				return nil, errors.New("interrupted before systemd accepted restart")
			}
			accepted = true
		}
		return nil, nil
	}
	if err := newManager(t, c, f).Install(ctx); err == nil {
		t.Fatal("expected interrupted restart")
	}
	resumed, err := Load(c.DataDir, f)
	if err != nil {
		t.Fatal(err)
	}
	if err = resumed.Install(ctx); err != nil {
		t.Fatal(err)
	}
	done, err := Load(c.DataDir, f)
	if err != nil || !done.Joined || done.restartPending || restarts != 2 {
		t.Fatal("interrupted credential reload did not complete durably")
	}
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call.args, " "), c.JoinToken) || strings.Contains(strings.Join(call.args, " "), old.Config.JoinToken) {
			t.Fatal("worker credential exposed in process arguments")
		}
	}
}

func TestInterruptedWorkerReloadDoesNotRestartAlreadyReadyNode(t *testing.T) {
	f := &fakeRunner{}
	m := pendingWorker(t, f)
	// K3s accepted the refreshed token and registered before the process could
	// clear its durable restart journal. The retry must only commit completion.
	m.restartPending = true
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	f.run = func(_ []byte, cmd string, args []string) ([]byte, error) {
		command := strings.Join(args, " ")
		if command == "--version" {
			return []byte(K3sVersion), nil
		}
		if strings.Contains(command, "get node") {
			return readyNode(m.Config.OverlayIP), nil
		}
		if cmd == "systemctl" && strings.HasPrefix(command, "restart ") {
			t.Fatal("resuming the credential journal restarted an already Ready worker")
		}
		return nil, nil
	}
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := Load(m.Config.DataDir, f)
	if err != nil || !saved.Joined || saved.restartPending {
		t.Fatal("completed credential reload was not durably recognized")
	}
}

func TestWorkerTokenRefreshCannotChangeInstallation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"address", func(c *Config) { c.OverlayIP = "100.64.0.3" }},
		{"name", func(c *Config) { c.Name = "worker-two" }},
		{"server", func(c *Config) { c.ServerURL = "https://100.64.0.3:6443" }},
		{"role", func(c *Config) { c.Role = "hub" }},
		{"pod-range", func(c *Config) { c.PodCIDR = "10.44.0.0/16" }},
		{"binary", func(c *Config) { c.K3sBinary = "/opt/k3s" }},
		{"cluster-ca", func(c *Config) {
			c.JoinToken = strings.Replace(c.JoinToken, strings.Repeat("a", 64), strings.Repeat("b", 64), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
				if args[0] != "--version" {
					t.Fatal("runtime touched after immutable configuration change")
				}
				return []byte(K3sVersion), nil
			}}
			old := pendingWorker(t, f)
			c := old.Config
			c.JoinToken = strings.Replace(c.JoinToken, "1111111111111111", "2222222222222222", 1)
			test.change(&c)
			if err := newManager(t, c, f).Install(context.Background()); err == nil {
				t.Fatal("token refresh changed the installation identity")
			}
			saved, err := Load(old.Config.DataDir, f)
			if err != nil || saved.Config.JoinToken != old.Config.JoinToken {
				t.Fatal("rejected change overwrote the saved credential")
			}
		})
	}
}

func TestWorkerTokenRefreshRejectsPreviouslyOrCurrentlyReadyNode(t *testing.T) {
	for _, durable := range []bool{true, false} {
		t.Run(map[bool]string{true: "committed-before-outage", false: "crashed-before-commit"}[durable], func(t *testing.T) {
			f := &fakeRunner{}
			old := pendingWorker(t, f)
			old.Joined = durable
			if err := old.Save(); err != nil {
				t.Fatal(err)
			}
			f.run = func(_ []byte, cmd string, args []string) ([]byte, error) {
				command := strings.Join(args, " ")
				if command == "--version" {
					return []byte(K3sVersion), nil
				}
				if strings.Contains(command, "get node") {
					if durable {
						t.Fatal("previously joined worker should not depend on API availability")
					}
					return readyNode(old.Config.OverlayIP), nil
				}
				if cmd == "systemctl" && strings.HasPrefix(command, "is-active ") {
					return nil, nil
				}
				t.Fatal("ready worker was restarted or reconfigured")
				return nil, nil
			}
			c := old.Config
			c.JoinToken = strings.Replace(c.JoinToken, "1111111111111111", "2222222222222222", 1)
			if err := newManager(t, c, f).Install(context.Background()); err == nil {
				t.Fatal("ready worker accepted credential rotation")
			}
			saved, err := Load(c.DataDir, f)
			if err != nil || !saved.Joined || saved.Config.JoinToken != old.Config.JoinToken {
				t.Fatal("ready worker did not preserve its confirmed installation")
			}
		})
	}
}

func TestHubProtectedPlacementLabelRequiresAdministrativeWrite(t *testing.T) {
	f := &fakeRunner{}
	m := newManager(t, config(t), f)
	ready, labeled := false, false
	f.run = func(_ []byte, _ string, args []string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch {
		case command == "--version":
			return []byte(K3sVersion), nil
		case strings.Contains(command, "--raw=/readyz"):
			return []byte("ok"), nil
		case strings.Contains(command, "get node"):
			ready = true
			return readyNode(m.Config.OverlayIP), nil
		case strings.Contains(command, "label node"):
			if !ready || !strings.Contains(command, ProtectedRoleLabel+"=hub --overwrite") || !strings.Contains(command, "--kubeconfig "+filepath.Join(m.Config.DataDir, "kubeconfig")) {
				t.Fatal("protected hub label was not applied through the ready administrator API")
			}
			labeled = true
		}
		return nil, nil
	}
	config, err := m.K3sConfig()
	if err != nil || strings.Contains(string(config), ProtectedRoleLabel) {
		t.Fatal("protected placement label delegated to kubelet")
	}
	if err = m.Install(context.Background()); err != nil || !labeled {
		t.Fatalf("hub completed without protected placement: %v", err)
	}
}
