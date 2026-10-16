package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

type workerExchange func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error)
type workerRunner func(context.Context, []byte, string, ...string) ([]byte, error)

func (r workerRunner) Run(ctx context.Context, input []byte, command string, args ...string) ([]byte, error) {
	return r(ctx, input, command, args...)
}

type expiringWorkerBackend struct{ lifecycleBackend }

func (b *expiringWorkerBackend) Token(_ context.Context, server bool) (string, error) {
	if server {
		return "", errors.New("worker requested server credentials")
	}
	b.tokens++
	return "K10" + strings.Repeat("a", 64) + fmt.Sprintf("::abcdef.%016d", b.tokens), nil
}

func pendingWorkerFixture(t *testing.T) (string, *installation, workerExchange, *coordinator.MemoryStore, *expiringWorkerBackend) {
	t.Helper()
	ctx := context.Background()
	hub := testInstallation(t.TempDir())
	hubID, err := hostnet.LoadOrCreateIdentity(hub.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	seed, hubNode, err := seedState(hubID, hub)
	if err != nil {
		t.Fatal(err)
	}
	store := &coordinator.MemoryStore{}
	control, err := coordinator.New(ctx, coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	err = control.Update(ctx, func(s *coordinator.State) error {
		s.Policy = seed.PacketFilter
		if err := coordinator.AllocateNode(s, hubNode); err != nil {
			return err
		}
		return enrollment.WriteRegistry(s, enrollment.Registry{Cluster: enrollment.Cluster{ID: hub.ClusterID, URL: hub.Services.PublicURL, HostCIDR: hub.Config.HostCIDR, PodCIDR: hub.Config.PodCIDR, ServiceCIDR: hub.Config.ServiceCIDR, DesiredVoters: 3}, Invites: map[string]*enrollment.Invite{}, Members: map[string]*enrollment.Member{hubNode.MachineKey: {Name: hubNode.Hostname, Role: "hub", Voter: true, Ready: true}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := &expiringWorkerBackend{lifecycleBackend: lifecycleBackend{probeReady: true}}
	broker := &enrollment.Broker{Store: store, Update: control.Update, Backend: backend}
	inv, err := broker.Invite(ctx, "worker", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	i := testInstallation(dir)
	i.Config.Name, i.Config.Role, i.Config.FirstHub, i.Config.Voter = "worker-one", "worker", false, false
	i.Config.SystemdDir = filepath.Join(dir, "units")
	i.Config.ServerURL = "https://" + hub.Config.OverlayIP + ":6443"
	i.Invitation = &inv
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := enrollment.Identity(dir)
	if err != nil {
		t.Fatal(err)
	}
	node := nodeFor(id, i.Config.Name, i.Config.Role, nil)
	exchange := func(ctx context.Context, inv enrollment.Invitation, key ed25519.PrivateKey, n coordinator.Node, action string) (enrollment.Grant, error) {
		if !bytes.Equal(key, signing) || n.MachineKey != node.MachineKey || n.NodeKey != node.NodeKey || n.DiscoKey != node.DiscoKey {
			return enrollment.Grant{}, errors.New("resume replaced enrolled identity")
		}
		signed := enrollment.Sign(enrollment.Request{ClusterID: inv.ClusterID, Action: action, Node: n, Issued: time.Now().UTC()}, key)
		body, _ := json.Marshal(signed)
		req := httptest.NewRequest("POST", "/v1/"+action, bytes.NewReader(body)).WithContext(ctx)
		if action == "enroll" {
			req.Header.Set("Authorization", "Bearer "+inv.Token)
		}
		response := httptest.NewRecorder()
		broker.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			return enrollment.Grant{}, fmt.Errorf("enrollment failed: HTTP %d", response.Code)
		}
		var grant enrollment.Grant
		if err := json.Unmarshal(response.Body.Bytes(), &grant); err != nil {
			return grant, err
		}
		return grant, enrollment.ValidateGrant(inv, n, grant, action == "confirm")
	}
	grant, err := exchange(ctx, inv, signing, node, "enroll")
	if err != nil {
		t.Fatal(err)
	}
	state := stateFromGrant(grant)
	if err = state.Validate(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = hostnet.SaveState(i.Config.AgentStateDir, state); err != nil {
		t.Fatal(err)
	}
	grant, err = exchange(ctx, inv, signing, node, "confirm")
	if err != nil {
		t.Fatal(err)
	}
	i.Config.OverlayIP, i.Config.JoinToken, i.Phase = grant.Self.Addresses[0].Addr().String(), grant.Token, "cluster"
	manager, err := cluster.New(i.Config, nil)
	if err != nil {
		t.Fatal(err)
	}
	i.Config = manager.Config
	if err = manager.Save(); err != nil {
		t.Fatal(err)
	}
	if err = saveInstallation(dir, i); err != nil {
		t.Fatal(err)
	}
	return dir, i, exchange, store, backend
}

func TestPendingWorkerRefreshesExpiredTokenWithSameSignedMembership(t *testing.T) {
	dir, i, exchange, store, backend := pendingWorkerFixture(t)
	ctx := context.Background()
	before, _ := store.Load(ctx)
	oldToken, oldConfig := i.Config.JoinToken, i.Config
	// A consumed invitation may expire while the pending worker is offline;
	// confirm authenticates its durable signing key, never the invitation again.
	i.Invitation.Expires = time.Now().Add(-48 * time.Hour)
	restarted := false
	runner := workerRunner(func(_ context.Context, _ []byte, command string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case joined == "--version":
			return []byte(cluster.K3sVersion), nil
		case command == "systemctl" && strings.HasPrefix(joined, "restart "):
			token, err := os.ReadFile(filepath.Join(i.Config.DataDir, "join-token"))
			if err != nil || strings.TrimSpace(string(token)) == oldToken || strings.TrimSpace(string(token)) != i.Config.JoinToken {
				t.Fatal("expired credential survived pending worker restart")
			}
			restarted = true
		case strings.Contains(joined, "get node"):
			if !restarted {
				return nil, errors.New("expired bootstrap token")
			}
			return []byte(`{"status":{"addresses":[{"type":"InternalIP","address":"` + i.Config.OverlayIP + `"}],"conditions":[{"type":"Ready","status":"True"}]}}`), nil
		}
		return nil, nil
	})
	if err := refreshPendingWorker(ctx, dir, i, runner, exchange); err != nil {
		t.Fatal(err)
	}
	if i.Config.JoinToken == oldToken || backend.tokens != 2 || i.Phase != "cluster" {
		t.Fatal("pending worker did not obtain one new restricted credential")
	}
	comparison := i.Config
	comparison.JoinToken = oldToken
	oldJSON, _ := json.Marshal(oldConfig)
	newJSON, _ := json.Marshal(comparison)
	if !bytes.Equal(oldJSON, newJSON) {
		t.Fatal("credential renewal changed immutable installation settings")
	}
	m, err := cluster.New(i.Config, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Install(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := cluster.Load(i.Config.DataDir, runner)
	if err != nil || !saved.Joined || !restarted {
		t.Fatal("worker failed to complete after token renewal")
	}
	after, _ := store.Load(ctx)
	if len(before.Nodes) != len(after.Nodes) {
		t.Fatal("resume allocated a second worker")
	}
	for machine, prior := range before.Nodes {
		next := after.Nodes[machine]
		if next == nil || next.ID != prior.ID || next.NodeKey != prior.NodeKey || next.Addresses[0] != prior.Addresses[0] {
			t.Fatal("signed reconfirmation changed registered node identity")
		}
	}
}

func TestPendingWorkerKeepsCompletedCredentialDuringCoordinatorOutage(t *testing.T) {
	dir, i, _, _, _ := pendingWorkerFixture(t)
	m, err := cluster.Load(i.Config.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Joined = true
	if err = m.Save(); err != nil {
		t.Fatal(err)
	}
	// Model a crash after completion but before a stale unified file is saved.
	i.Config.JoinToken = strings.Replace(i.Config.JoinToken, "0000000000000001", "0000000000000099", 1)
	fail := func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
		t.Fatal("completed worker tried to renew through unavailable coordinator")
		return enrollment.Grant{}, nil
	}
	if err = refreshPendingWorker(context.Background(), dir, i, workerRunner(func(context.Context, []byte, string, ...string) ([]byte, error) {
		t.Fatal("durably joined worker probed unavailable API")
		return nil, nil
	}), fail); err != nil {
		t.Fatal(err)
	}
	if i.Config.JoinToken != m.Config.JoinToken {
		t.Fatal("did not recover the confirmed cluster credential")
	}
}

func TestPendingWorkerRejectsReallocatedGrantAndMissingIdentity(t *testing.T) {
	for _, which := range []string{"address", "range", "server", "ca", "signing-key", "overlay-key"} {
		t.Run(which, func(t *testing.T) {
			dir, i, exchange, _, _ := pendingWorkerFixture(t)
			before, err := os.ReadFile(filepath.Join(dir, "unified.json"))
			if err != nil {
				t.Fatal(err)
			}
			var missing string
			if which == "signing-key" {
				missing = filepath.Join(dir, "enrollment.key")
			} else if which == "overlay-key" {
				missing = filepath.Join(i.Config.AgentStateDir, "identity.json")
			}
			if missing != "" {
				if err := os.Remove(missing); err != nil {
					t.Fatal(err)
				}
			}
			runner := workerRunner(func(context.Context, []byte, string, ...string) ([]byte, error) { return nil, errors.New("not joined") })
			change := func(ctx context.Context, inv enrollment.Invitation, key ed25519.PrivateKey, n coordinator.Node, action string) (enrollment.Grant, error) {
				if missing != "" {
					t.Fatal("recovery contacted coordinator without original keys")
				}
				g, err := exchange(ctx, inv, key, n, action)
				switch which {
				case "address":
					g.Self.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.77/32")}
				case "range":
					g.Cluster.PodCIDR = "10.44.0.0/16"
				case "server":
					g.ServerURLs = []string{"https://100.64.0.8:6443"}
				case "ca":
					g.Token = strings.Replace(g.Token, strings.Repeat("a", 64), strings.Repeat("b", 64), 1)
				}
				return g, err
			}
			if err := refreshPendingWorker(context.Background(), dir, i, runner, change); err == nil {
				t.Fatal("unsafe pending worker recovery succeeded")
			}
			after, err := os.ReadFile(filepath.Join(dir, "unified.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed recovery changed the saved installation")
			}
			if missing != "" {
				if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recovery generated a replacement private key")
				}
			}
		})
	}
}
