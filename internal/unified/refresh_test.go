package unified

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type refreshFixture struct {
	dir      string
	i        *installation
	id       *hostnet.Identity
	saved    *hostnet.State
	control  *coordinator.Server
	store    *coordinator.MemoryStore
	fetch    refreshMapFunc
	original []byte
	identity []byte
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	f := &refreshFixture{dir: t.TempDir(), store: new(coordinator.MemoryStore)}
	f.i = testInstallation(f.dir)
	var err error
	f.id, err = hostnet.LoadOrCreateIdentity(f.i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	var node *coordinator.Node
	f.saved, node, err = seedState(f.id, f.i)
	if err != nil {
		t.Fatal(err)
	}
	f.saved.UpdatedAt = time.Now().Add(-31 * 24 * time.Hour)
	f.saved.ExpiresAt = f.saved.UpdatedAt.Add(hostnet.CacheLifetime)
	oldPeer := &coordinator.Node{ID: 2, MachineKey: key.NewMachine().Public().String(), NodeKey: key.NewNode().Public().String(), DiscoKey: key.NewDisco().Public().String(), Role: "hub", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:41641")}}
	f.saved.Peers = []*tailcfg.Node{oldPeer.TailNode()}
	f.saved.DirectHubEndpoints[f.saved.Peers[0].Key] = slices.Clone(f.saved.Peers[0].Endpoints)
	f.saved.DERPMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{7: {RegionID: 7}}}
	f.saved.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.20.0/24")}
	f.control, err = coordinator.New(context.Background(), coordinator.Config{Store: f.store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.control.Close() })
	if err = f.control.Update(context.Background(), func(s *coordinator.State) error {
		s.Policy = []tailcfg.FilterRule{}
		node.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")}
		return coordinator.AllocateNode(s, node)
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.control.Handler())
	t.Cleanup(server.Close)
	f.fetch = func(ctx context.Context, origin string, id *hostnet.Identity) (*tailcfg.MapResponse, error) {
		if origin != f.i.Services.PublicURL || id.Machine.Public() != f.id.Machine.Public() || id.Node.Public() != f.id.Node.Public() {
			t.Fatal("refresh used another origin or identity")
		}
		// The production callback verifies HTTPS. This loopback-only test speaks
		// the real Noise protocol to exercise authentication and revocation.
		client := coordinator.Client{ServerURL: server.URL, MachineKey: id.Machine}
		return client.Map(ctx, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: id.Node.Public(), DiscoKey: id.Disco.Public(), ReadOnly: true})
	}
	f.persist(t)
	f.identity, err = os.ReadFile(filepath.Join(f.i.Config.AgentStateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *refreshFixture) persist(t *testing.T) {
	t.Helper()
	var err error
	f.original, err = json.Marshal(f.saved)
	if err != nil {
		t.Fatal(err)
	}
	if err = platform.WriteFile(filepath.Join(f.i.Config.AgentStateDir, "overlay.json"), f.original, false); err != nil {
		t.Fatal(err)
	}
	if err = saveInstallation(f.dir, f.i); err != nil {
		t.Fatal(err)
	}
}

func (f *refreshFixture) unchanged(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(f.i.Config.AgentStateDir, "overlay.json"))
	if err != nil || !bytes.Equal(got, f.original) {
		t.Fatal("failed refresh changed the original cache")
	}
	got, err = os.ReadFile(filepath.Join(f.i.Config.AgentStateDir, "identity.json"))
	if err != nil || !bytes.Equal(got, f.identity) {
		t.Fatal("refresh changed the private identity")
	}
}

func TestExpiredCacheRefreshAuthenticatesAndDiscardsStaleAuthority(t *testing.T) {
	f := newRefreshFixture(t)
	if _, err := hostnet.LoadState(f.i.Config.AgentStateDir); err == nil {
		t.Fatal("fixture was not expired")
	}
	before, _ := f.store.Load(context.Background())
	if err := refreshSavedNetwork(context.Background(), f.dir, f.fetch); err != nil {
		t.Fatal(err)
	}
	fresh, err := hostnet.LoadState(f.i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = fresh.Validate(f.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(fresh.Peers) != 0 || len(fresh.PacketFilter) != 0 || len(fresh.DERPMap.Regions) != 0 || len(fresh.DirectHubEndpoints) != 1 {
		t.Fatal("refresh retained stale peers, packet grants, relay map, or endpoints")
	}
	if !slices.Equal(fresh.DirectHubEndpoints[f.id.Node.Public()], []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")}) {
		t.Fatal("fresh map did not replace the stale local endpoint")
	}
	if !slices.Equal(fresh.ApprovedRoutes, f.saved.ApprovedRoutes) || !fresh.UpdatedAt.After(f.saved.ExpiresAt) {
		t.Fatal("refresh lost local opt-ins or failed to commit current trust")
	}
	after, _ := f.store.Load(context.Background())
	if before.Revision != after.Revision {
		t.Fatal("read-only refresh changed coordinator state")
	}
	identity, _ := os.ReadFile(filepath.Join(f.i.Config.AgentStateDir, "identity.json"))
	if !bytes.Equal(identity, f.identity) {
		t.Fatal("refresh rotated private keys")
	}
}

func TestCacheRefreshRejectsRevocationAndTLSFailureWithoutWriting(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		f := newRefreshFixture(t)
		if err := f.control.Update(context.Background(), func(s *coordinator.State) error { s.Nodes[f.id.Machine.Public().String()].Revoked = true; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := refreshSavedNetwork(context.Background(), f.dir, f.fetch); err == nil {
			t.Fatal("revoked identity recovered stale authority")
		}
		f.unchanged(t)
	})
	t.Run("untrusted-TLS", func(t *testing.T) {
		f := newRefreshFixture(t)
		server := httptest.NewTLSServer(f.control.Handler())
		defer server.Close()
		f.i.Services.PublicURL, f.saved.CoordinatorURL = server.URL, server.URL
		f.persist(t)
		if err := refreshSavedNetwork(context.Background(), f.dir, authenticatedRefreshMap); err == nil {
			t.Fatal("refresh accepted an untrusted HTTPS certificate")
		}
		f.unchanged(t)
	})
}

func TestCacheRefreshDoesNotCarryOldEndpointsForRetainedPeer(t *testing.T) {
	f := newRefreshFixture(t)
	peer := f.saved.Peers[0].Clone()
	peer.Endpoints = nil
	fetch := func(ctx context.Context, origin string, id *hostnet.Identity) (*tailcfg.MapResponse, error) {
		m, err := f.fetch(ctx, origin, id)
		if err == nil {
			m.Peers = []*tailcfg.Node{peer}
		}
		return m, err
	}
	if err := refreshSavedNetwork(context.Background(), f.dir, fetch); err != nil {
		t.Fatal(err)
	}
	fresh, err := hostnet.LoadState(f.i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Peers) != 1 || len(fresh.Peers[0].Endpoints) != 0 || len(fresh.DirectHubEndpoints[peer.Key]) != 0 {
		t.Fatal("retained peer inherited expired-cache endpoint authority")
	}
}

func TestCacheRefreshRejectsPartialOrChangedIdentityMaps(t *testing.T) {
	for name, change := range map[string]func(*tailcfg.MapResponse){
		"policy-omitted": func(m *tailcfg.MapResponse) { m.PacketFilter = nil },
		"peers-omitted":  func(m *tailcfg.MapResponse) { m.Peers = nil },
		"relay-omitted":  func(m *tailcfg.MapResponse) { m.DERPMap = nil },
		"old-response":   func(m *tailcfg.MapResponse) { old := time.Now().Add(-time.Hour); m.ControlTime = &old },
		"wrong-node":     func(m *tailcfg.MapResponse) { m.Node.Key = key.NewNode().Public() },
		"wrong-disco":    func(m *tailcfg.MapResponse) { m.Node.DiscoKey = key.NewDisco().Public() },
		"wrong-address": func(m *tailcfg.MapResponse) {
			m.Node.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}
		},
		"unauthorized": func(m *tailcfg.MapResponse) { m.Node.MachineAuthorized = false },
		"expired-key":  func(m *tailcfg.MapResponse) { m.Node.KeyExpiry = time.Now().Add(-time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshFixture(t)
			fetch := func(ctx context.Context, origin string, id *hostnet.Identity) (*tailcfg.MapResponse, error) {
				m, err := f.fetch(ctx, origin, id)
				if err == nil {
					change(m)
				}
				return m, err
			}
			if err := refreshSavedNetwork(context.Background(), f.dir, fetch); err == nil {
				t.Fatal("invalid map replaced the expired cache")
			}
			f.unchanged(t)
		})
	}
}

func TestCacheRefreshRefusesMalformedStateOrConcurrentAgent(t *testing.T) {
	for name, change := range map[string]func(*refreshFixture){
		"identity-mismatch": func(f *refreshFixture) { f.saved.Self.Key = key.NewNode().Public() },
		"bad-policy":        func(f *refreshFixture) { f.saved.PacketFilter[0].SrcIPs = []string{"invalid"} },
		"bad-peer":          func(f *refreshFixture) { f.saved.Peers[0].Addresses = nil },
		"wrong-cluster":     func(f *refreshFixture) { f.saved.ClusterID = "another" },
		"wrong-origin":      func(f *refreshFixture) { f.saved.CoordinatorURL = "https://other.example.com" },
		"HTTP-origin": func(f *refreshFixture) {
			f.saved.CoordinatorURL = "http://connect.example.com"
			f.i.Services.PublicURL = f.saved.CoordinatorURL
		},
		"invalid-installation-address": func(f *refreshFixture) { f.i.Config.OverlayIP = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshFixture(t)
			change(f)
			f.persist(t)
			if err := refreshSavedNetwork(context.Background(), f.dir, func(context.Context, string, *hostnet.Identity) (*tailcfg.MapResponse, error) {
				t.Fatal("invalid local state reached the network")
				return nil, nil
			}); err == nil {
				t.Fatal("invalid state was accepted")
			}
			f.unchanged(t)
		})
	}
	t.Run("agent-active", func(t *testing.T) {
		f := newRefreshFixture(t)
		unlock, err := platform.Lock(filepath.Join(f.i.Config.AgentStateDir, "agent-lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		if err := refreshSavedNetwork(context.Background(), f.dir, f.fetch); err == nil {
			t.Fatal("active agent did not prevent concurrent cache replacement")
		}
		f.unchanged(t)
	})
	t.Run("missing-identity", func(t *testing.T) {
		f := newRefreshFixture(t)
		path := filepath.Join(f.i.Config.AgentStateDir, "identity.json")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := refreshSavedNetwork(context.Background(), f.dir, f.fetch); err == nil {
			t.Fatal("missing identity was accepted")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refresh recreated identity")
		}
		got, _ := os.ReadFile(filepath.Join(f.i.Config.AgentStateDir, "overlay.json"))
		if !bytes.Equal(got, f.original) {
			t.Fatal("missing-identity failure changed cache")
		}
	})
}
