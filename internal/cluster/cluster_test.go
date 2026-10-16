package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type call struct {
	input   []byte
	command string
	args    []string
}
type fakeRunner struct {
	calls []call
	run   func([]byte, string, []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, input []byte, command string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{append([]byte(nil), input...), command, append([]string(nil), args...)})
	if f.run != nil {
		return f.run(input, command, args)
	}
	return nil, nil
}
func config(t *testing.T) Config {
	t.Helper()
	return Config{Name: "hub-one", Role: "hub", FirstHub: true, Voter: true, OverlayIP: "100.64.0.1", DataDir: filepath.Join(t.TempDir(), "state"), SystemdDir: filepath.Join(t.TempDir(), "units")}
}
func secureJoin() string { return "K10" + strings.Repeat("a", 64) + "::server:credential" }
func readyNode(ip string) []byte {
	return []byte(`{"metadata":{"labels":{"connect.deepai.cloud/voter":"true"}},"status":{"addresses":[{"type":"InternalIP","address":"` + ip + `"}],"conditions":[{"type":"Ready","status":"True"}]}}`)
}
func newManager(t *testing.T, c Config, f *fakeRunner) *Manager {
	t.Helper()
	m, err := New(c, f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestK3sRolesShareOverlayAndDatastore(t *testing.T) {
	for _, role := range []string{"first-hub", "voter", "non-voter", "worker"} {
		t.Run(role, func(t *testing.T) {
			c := config(t)
			if role != "first-hub" {
				c.FirstHub = false
				c.ServerURL = "https://100.64.0.1:6443"
				c.JoinToken = secureJoin()
			}
			if role == "non-voter" {
				c.Voter = false
			}
			if role == "worker" {
				c.Role = "worker"
				c.Voter = false
			}
			m := newManager(t, c, &fakeRunner{})
			data, err := m.K3sConfig()
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err = json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got["node-ip"] != c.OverlayIP || got["flannel-iface"] != "deepai0" {
				t.Fatal("Kubernetes traffic must use the existing host overlay")
			}
			if role == "first-hub" && got["cluster-init"] != true {
				t.Fatal("first hub must initialize embedded etcd")
			}
			if role != "first-hub" {
				if _, ok := got["cluster-init"]; ok {
					t.Fatal("join initialized a separate cluster")
				}
				if got["server"] != c.ServerURL {
					t.Fatal("join server missing")
				}
			}
			if role == "non-voter" && got["disable-etcd"] != true {
				t.Fatal("non-voter hub adds an etcd member")
			}
			if role == "worker" {
				if _, ok := got["cluster-cidr"]; ok {
					t.Fatal("worker has server-only flags")
				}
			}
			if strings.Contains(string(data), c.JoinToken) && c.JoinToken != "" {
				t.Fatal("credential embedded in Kubernetes configuration")
			}
			if !strings.Contains(m.Unit(), "Requires="+AgentUnitName) || !strings.Contains(m.Unit(), "After=network-online.target "+AgentUnitName) {
				t.Fatal("overlay restoration must precede Kubernetes")
			}
		})
	}
}
func TestConfigRejectsUnsafeTopology(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"overlap", func(c *Config) { c.PodCIDR = "100.64.0.0/16" }},
		{"outside-overlay", func(c *Config) { c.OverlayIP = "192.168.0.2" }},
		{"even-target", func(c *Config) { c.DesiredVoters = 4 }},
		{"worker-voter", func(c *Config) { c.Role = "worker" }},
		{"nonvoter-bootstrap", func(c *Config) { c.Voter = false }},
		{"join-public-endpoint", func(c *Config) {
			c.FirstHub = false
			c.ServerURL = "https://example.com:6443"
			c.JoinToken = secureJoin()
		}},
		{"untrusted-token", func(c *Config) { c.FirstHub = false; c.ServerURL = "https://100.64.0.2:6443"; c.JoinToken = "password" }},
		{"relative-path", func(c *Config) { c.K3sBinary = "./k3s" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := config(t)
			tc.change(&c)
			if _, err := New(c, &fakeRunner{}); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func TestInstallPersistsBeforeStartAndDoesNotExposeToken(t *testing.T) {
	c := config(t)
	c.FirstHub = false
	c.ServerURL = "https://100.64.0.2:6443"
	c.JoinToken = secureJoin()
	f := &fakeRunner{run: func(input []byte, cmd string, args []string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch {
		case command == "--version":
			return []byte("k3s version " + K3sVersion + " (abc)"), nil
		case strings.Contains(command, "enable --now"):
			if _, err := os.Stat(filepath.Join(c.DataDir, "cluster.json")); err != nil {
				t.Fatal("started Kubernetes without durable state")
			}
		case strings.Contains(command, "--raw=/readyz"):
			return []byte("ok\n"), nil
		case strings.Contains(command, "get node"):
			return readyNode(c.OverlayIP), nil
		}
		return nil, nil
	}}
	m := newManager(t, c, f)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call.args, " "), c.JoinToken) {
			t.Fatal("join secret exposed in process arguments")
		}
	}
	for _, name := range []string{"cluster.json", "join-token", "k3s-config.yaml"} {
		fi, err := os.Stat(filepath.Join(c.DataDir, name))
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("%s not protected: %v", name, err)
		}
	}
	loaded, err := Load(c.DataDir, f)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.JoinToken != c.JoinToken {
		t.Fatal("cannot resume saved enrollment")
	}
	changed := loaded.Config
	changed.OverlayIP = "100.64.0.7"
	if err = newManager(t, changed, f).Install(context.Background()); err == nil {
		t.Fatal("silently rewrote established host identity")
	}
}
func TestInstallRequiresPinnedBinaryAndHealthyAgent(t *testing.T) {
	for _, which := range []string{"version", "agent"} {
		t.Run(which, func(t *testing.T) {
			c := config(t)
			f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
				if args[0] == "--version" {
					if which == "version" {
						return []byte("v1.20.0+k3s1"), nil
					}
					return []byte(K3sVersion), nil
				}
				return nil, errors.New("not active")
			}}
			m := newManager(t, c, f)
			if err := m.Install(context.Background()); err == nil {
				t.Fatal("unsafe install succeeded")
			}
			if _, err := os.Stat(c.DataDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("changed persistent state before prerequisites passed")
			}
		})
	}
}
func TestReadyRejectsNodeUsingPublicAddress(t *testing.T) {
	m := newManager(t, config(t), &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "--raw=/readyz") {
			return []byte("ok"), nil
		}
		return readyNode("192.0.2.1"), nil
	}})
	if err := m.ready(context.Background()); err == nil {
		t.Fatal("accepted node registered outside overlay")
	}
}
func TestSystemdLiteralPaths(t *testing.T) {
	c := config(t)
	c.K3sBinary = "/opt/100%/$thing/k3s"
	m := newManager(t, c, &fakeRunner{})
	if !strings.Contains(m.Unit(), `"/opt/100%%/$$thing/k3s"`) {
		t.Fatal("systemd path expansion not escaped")
	}
}

func TestSystemdWaitsForOverlayReadinessOnEveryBoot(t *testing.T) {
	m := newManager(t, config(t), &fakeRunner{})
	unit := m.Unit()
	want := "ExecStartPre=" + systemdQuote(m.Config.ConnectBinary) + " agent-ready --dir " + systemdQuote(filepath.Dir(m.Config.AgentStateDir))
	if !strings.Contains(unit, want) {
		t.Fatal("K3s can start before the host agent restores its cached overlay")
	}
}
func TestInstallRefusesOrphanOrForeignManagedUnit(t *testing.T) {
	for _, orphan := range []bool{true, false} {
		t.Run(map[bool]string{true: "orphan", false: "foreign"}[orphan], func(t *testing.T) {
			f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
				if args[0] == "--version" {
					return []byte(K3sVersion), nil
				}
				t.Fatal("systemd called after ownership conflict")
				return nil, nil
			}}
			m := newManager(t, config(t), f)
			if err := os.MkdirAll(m.Config.SystemdDir, 0700); err != nil {
				t.Fatal(err)
			}
			unit := m.Unit()
			if !orphan {
				if err := m.Save(); err != nil {
					t.Fatal(err)
				}
				unit = strings.Replace(unit, "agent-ready", "other-command", 1)
			}
			path := filepath.Join(m.Config.SystemdDir, UnitName)
			if err := os.WriteFile(path, []byte(unit), 0600); err != nil {
				t.Fatal(err)
			}
			if err := m.Install(context.Background()); err == nil {
				t.Fatal("existing unrelated systemd installation overwritten")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != unit {
				t.Fatal("unit mutated despite ownership conflict")
			}
		})
	}
}
