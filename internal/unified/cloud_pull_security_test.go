package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"tailscale.com/types/key"
)

func configurationPullFixture(t *testing.T) (string, *installation, enrollment.Grant) {
	t.Helper()
	dir := t.TempDir()
	i := testInstallation(dir)
	i.Config.FirstHub, i.Config.Role, i.Config.Voter = false, "worker", false
	i.Config.Name, i.Config.ConnectImage = "worker-one", "registry.example.com/connect:v1"
	i.Config.OverlayIP, i.PublicIP = "100.64.0.2", ""
	i.Invitation = &enrollment.Invitation{
		ClusterID: i.ClusterID, URL: i.Services.PublicURL, Role: "worker",
		Name: i.Config.Name, Expires: time.Now().Add(-time.Hour),
	}
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.Identity(dir); err != nil {
		t.Fatal(err)
	}
	if err := saveInstallation(dir, i); err != nil {
		t.Fatal(err)
	}
	node := nodeFor(id, i.Config.Name, i.Config.Role, nil)
	node.ID = 2
	node.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
	g := enrollment.Grant{
		Cluster: enrollment.Cluster{
			ID: i.ClusterID, URL: i.Services.PublicURL, HostCIDR: i.Config.HostCIDR,
			PodCIDR: i.Config.PodCIDR, ServiceCIDR: i.Config.ServiceCIDR,
			DesiredVoters: i.Config.DesiredVoters, Image: i.Config.ConnectImage,
		},
		Role: "worker", Self: node.TailNode(), ServerURLs: []string{"https://100.64.0.1:6443"},
		Configuration: &enrollment.NodeConfiguration{
			Revision: strings.Repeat("a", 64), Name: i.Config.Name,
			Node: cloudconfig.Node{Role: "worker", Labels: map[string]string{"location": "home"}},
		},
	}
	if err := hostnet.SaveState(i.Config.AgentStateDir, stateFromGrant(g)); err != nil {
		t.Fatal(err)
	}
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err != nil {
		t.Fatal(err)
	}
	return dir, i, g
}

func grantExchange(g enrollment.Grant) configExchange {
	return func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
		return g, nil
	}
}

func configurationFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	snapshot := make(map[string][]byte)
	for _, name := range []string{"unified.json", "configuration.json", "enrollment.key", "network/identity.json", "network/overlay.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[name] = b
	}
	return snapshot
}

func assertConfigurationFilesUnchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	for name, expected := range before {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("%s changed after rejected pull: %v", name, err)
		}
	}
}

func TestConfigurationPullRejectsTamperingWithoutChangingRecoveryState(t *testing.T) {
	tests := []struct {
		name   string
		change func(*enrollment.Grant)
	}{
		{"cluster", func(g *enrollment.Grant) { g.Cluster.ID = "another-cluster" }},
		{"origin", func(g *enrollment.Grant) { g.Cluster.URL = "https://another.example.com" }},
		{"role", func(g *enrollment.Grant) { g.Role = "hub" }},
		{"voter", func(g *enrollment.Grant) { g.Voter = true }},
		{"missing-self", func(g *enrollment.Grant) { g.Self = nil }},
		{"machine-key", func(g *enrollment.Grant) { g.Self.Machine = key.NewMachine().Public() }},
		{"node-key", func(g *enrollment.Grant) { g.Self.Key = key.NewNode().Public() }},
		{"overlay-ip", func(g *enrollment.Grant) { g.Self.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")} }},
		{"host-range", func(g *enrollment.Grant) { g.Cluster.HostCIDR = "100.64.0.0/16" }},
		{"pod-range", func(g *enrollment.Grant) { g.Cluster.PodCIDR = "10.52.0.0/16" }},
		{"service-range", func(g *enrollment.Grant) { g.Cluster.ServiceCIDR = "10.53.0.0/16" }},
		{"image", func(g *enrollment.Grant) { g.Cluster.Image = "registry.example.com/connect:v2" }},
		{"voter-count", func(g *enrollment.Grant) { g.Cluster.DesiredVoters = 5 }},
		{"credentials", func(g *enrollment.Grant) { g.Token = "must-never-be-cached" }},
		{"missing-config", func(g *enrollment.Grant) { g.Configuration = nil }},
		{"config-name", func(g *enrollment.Grant) { g.Configuration.Name = "another-worker" }},
		{"config-role", func(g *enrollment.Grant) { g.Configuration.Node.Role = "hub" }},
		{"config-voter", func(g *enrollment.Grant) { g.Configuration.Node.Voter = true }},
		{"config-public-ip", func(g *enrollment.Grant) { g.Configuration.Node.PublicIP = "203.0.113.10" }},
		{"config-relay", func(g *enrollment.Grant) { g.Configuration.Node.RelayDomain = "relay.example.com" }},
		{"config-ssh", func(g *enrollment.Grant) { g.Configuration.Node.Connection.SSH = "root@hub.example.com" }},
		{"config-revision", func(g *enrollment.Grant) { g.Configuration.Revision = strings.Repeat("z", 64) }},
		{"reserved-label", func(g *enrollment.Grant) {
			g.Configuration.Node.Labels["node-role.kubernetes.io/control-plane"] = "true"
		}},
		{"invalid-label", func(g *enrollment.Grant) { g.Configuration.Node.Labels["location"] = "not a label" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, g := configurationPullFixture(t)
			before := configurationFiles(t, dir)
			tc.change(&g)
			if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err == nil {
				t.Fatal("tampered grant was accepted")
			}
			assertConfigurationFilesUnchanged(t, dir, before)
		})
	}
}

func TestConfigurationPullDoesNotRegenerateLostOrCorruptIdentities(t *testing.T) {
	for _, name := range []string{"enrollment.key", "network/identity.json"} {
		for _, corrupt := range []bool{false, true} {
			label := name + "/missing"
			if corrupt {
				label = name + "/corrupt"
			}
			t.Run(label, func(t *testing.T) {
				dir, _, _ := configurationPullFixture(t)
				path := filepath.Join(dir, name)
				if corrupt {
					if err := os.WriteFile(path, []byte("corrupt existing identity"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before := configurationFiles(t, dir)
				if !corrupt {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					delete(before, name)
				}
				exchange := func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
					t.Fatal("pull contacted the hub without the original identity")
					return enrollment.Grant{}, nil
				}
				if err := pullConfiguration(context.Background(), dir, exchange); err == nil {
					t.Fatal("missing or corrupt identity was accepted")
				}
				assertConfigurationFilesUnchanged(t, dir, before)
				if !corrupt {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("missing identity was regenerated: %v", err)
					}
				}
			})
		}
	}
}

func TestConfigurationPullFailureCancellationAndRetry(t *testing.T) {
	dir, _, g := configurationPullFixture(t)
	before := configurationFiles(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := pullConfiguration(ctx, dir, func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
		called = true
		return g, nil
	}); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled pull started an exchange: called=%v err=%v", called, err)
	}
	offline := errors.New("hub unavailable")
	if err := pullConfiguration(context.Background(), dir, func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
		return enrollment.Grant{}, offline
	}); !errors.Is(err, offline) {
		t.Fatalf("offline failure was hidden: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	g.Configuration.Revision = strings.Repeat("b", 64)
	g.Configuration.Node.Labels["location"] = "office"
	if err := pullConfiguration(ctx, dir, func(ctx context.Context, _ enrollment.Invitation, _ ed25519.PrivateKey, _ coordinator.Node, _ string) (enrollment.Grant, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Error("pull has no bounded request deadline")
		}
		cancel()
		return g, nil // A response that races with cancellation must not commit.
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("late response ignored cancellation: %v", err)
	}
	assertConfigurationFilesUnchanged(t, dir, before)
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err != nil {
		t.Fatalf("retry retained a failed pull's lock: %v", err)
	}
	delete(before, "configuration.json")
	assertConfigurationFilesUnchanged(t, dir, before)
	raw, err := os.ReadFile(filepath.Join(dir, "configuration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved savedNodeConfiguration
	if err := json.Unmarshal(raw, &saved); err != nil || saved.Revision != g.Configuration.Revision || saved.Node.Labels["location"] != "office" {
		t.Fatalf("retry did not receive the latest desired configuration: %v", err)
	}
}

func TestConfigurationPullSerializesRequestsBeforeFetching(t *testing.T) {
	dir, _, g := configurationPullFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		done <- pullConfiguration(ctx, dir, func(ctx context.Context, _ enrollment.Invitation, _ ed25519.PrivateKey, _ coordinator.Node, _ string) (enrollment.Grant, error) {
			close(started)
			select {
			case <-release:
				return g, nil
			case <-ctx.Done():
				return enrollment.Grant{}, ctx.Err()
			}
		})
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("first pull failed to start: %v", err)
	case <-ctx.Done():
		t.Fatal("first pull did not start")
	}
	called := false
	err := pullConfiguration(context.Background(), dir, func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
		called = true
		return g, nil
	})
	close(release)
	if firstErr := <-done; firstErr != nil {
		t.Fatal(firstErr)
	}
	if err == nil || called {
		t.Fatalf("overlapping request could commit out of order: called=%v err=%v", called, err)
	}
	g.Configuration.Revision = strings.Repeat("b", 64)
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err != nil {
		t.Fatalf("retry after contention failed: %v", err)
	}
	var saved savedNodeConfiguration
	raw, err := os.ReadFile(filepath.Join(dir, "configuration.json"))
	if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Revision != g.Configuration.Revision {
		t.Fatalf("latest revision was not committed: %v", err)
	}
}

func TestConfigurationPullPreservesIdenticalCacheAndRequiresAdoptedConfiguration(t *testing.T) {
	dir, i, g := configurationPullFixture(t)
	path := filepath.Join(dir, "configuration.json")
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("configuration cache is not private: %v", err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil || !info.ModTime().Equal(old) {
		t.Fatalf("unchanged configuration was unnecessarily rewritten: %v", err)
	}
	// Legacy invitations can be adopted by cloud.yaml later; an existing
	// configuration cache then proves that this node requires configuration.
	i.Invitation.Name = ""
	if err := saveInstallation(dir, i); err != nil {
		t.Fatal(err)
	}
	before := configurationFiles(t, dir)
	g.Configuration = nil
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err == nil {
		t.Fatal("adopted node silently accepted missing configuration")
	}
	assertConfigurationFilesUnchanged(t, dir, before)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err != nil {
		t.Fatalf("legacy undeclared node must still support configuration pulls: %v", err)
	}
	g.Token = "cluster-token-must-not-be-accepted"
	if err := pullConfiguration(context.Background(), dir, grantExchange(g)); err == nil {
		t.Fatal("undeclared node accepted credentials in a configuration response")
	}
}
