package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type countedMapStore struct {
	Store
	loads, writes int
}

func (s *countedMapStore) Load(ctx context.Context) (*State, error) {
	s.loads++
	return s.Store.Load(ctx)
}

func (s *countedMapStore) CompareAndSwap(ctx context.Context, st *State, revision string) error {
	s.writes++
	return s.Store.CompareAndSwap(ctx, st, revision)
}

func TestMapRequestsAvoidRedundantStateLoads(t *testing.T) {
	for _, tc := range []struct {
		name         string
		readOnly     bool
		omitPeers    bool
		unauthorized bool
		loads        int
		writes       int
	}{
		{name: "read-only", readOnly: true, loads: 1},
		{name: "read-only-omit", readOnly: true, omitPeers: true, loads: 1},
		{name: "update-and-map", loads: 2, writes: 1},
		{name: "update-only", omitPeers: true, loads: 1, writes: 1},
		{name: "unauthorized-read-only", readOnly: true, unauthorized: true, loads: 1},
		{name: "unauthorized-read-only-omit", readOnly: true, omitPeers: true, unauthorized: true, loads: 1},
		{name: "unauthorized-update", unauthorized: true, loads: 1},
		{name: "unauthorized-update-only", omitPeers: true, unauthorized: true, loads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := NewState()
			n, m, k := testIdentity("client")
			if err := AllocateNode(st, &n); err != nil {
				t.Fatal(err)
			}
			memory := &MemoryStore{}
			if err := memory.CompareAndSwap(context.Background(), st, ""); err != nil {
				t.Fatal(err)
			}
			store := &countedMapStore{Store: memory}
			s, _ := newServer(t, store)
			if tc.unauthorized {
				k = key.NewNode()
			}
			body, err := json.Marshal(tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: k.Public(), ReadOnly: tc.readOnly, OmitPeers: tc.omitPeers})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.serveMap(w, httptest.NewRequest("POST", "/machine/map", bytes.NewReader(body)), m.Public())
			wantStatus := http.StatusOK
			if tc.unauthorized {
				wantStatus = http.StatusUnauthorized
			}
			if w.Code != wantStatus {
				t.Fatalf("status %d, want %d: %s", w.Code, wantStatus, w.Body.String())
			}
			if store.loads != tc.loads || store.writes != tc.writes {
				t.Fatalf("loads/writes = %d/%d; want %d/%d", store.loads, store.writes, tc.loads, tc.writes)
			}
			if !tc.unauthorized && (tc.readOnly || !tc.omitPeers) {
				msg, err := readMap(w.Body, false)
				if err != nil || msg.Node.Key != k.Public() {
					t.Fatalf("map response: %v, %v", msg, err)
				}
			}
		})
	}
}

func newServer(t *testing.T, store Store) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(context.Background(), Config{Store: store, AdminToken: "test-admin-token", PollInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); ts.Close() })
	return s, ts
}
func testIdentity(role string) (Node, key.MachinePrivate, key.NodePrivate) {
	m, n, d := key.NewMachine(), key.NewNode(), key.NewDisco()
	return Node{MachineKey: m.Public().String(), NodeKey: n.Public().String(), DiscoKey: d.Public().String(), Hostname: "test", Role: role}, m, n
}

func TestNoiseRegistrationMapAndReplicaFailover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store := &MemoryStore{}
	s, ts := newServer(t, store)
	replica, replicaHTTP := newServer(t, store)
	if s.PublicKey() != replica.PublicKey() {
		t.Fatal("replicas have different server identity")
	}
	token, err := s.CreateInvitation(ctx, Invitation{Role: "client", UsesRemaining: 2})
	if err != nil {
		t.Fatal(err)
	}
	n1, m1, k1 := testIdentity("client")
	n2, m2, k2 := testIdentity("client")
	c1 := &Client{ServerURL: ts.URL, MachineKey: m1, ServerKey: s.PublicKey()}
	c2 := &Client{ServerURL: replicaHTTP.URL, MachineKey: m2, ServerKey: s.PublicKey()}
	for i, pair := range []struct {
		client  *Client
		n       Node
		nodeKey key.NodePrivate
	}{{c1, n1, k1}, {c2, n2, k2}} {
		reply, err := pair.client.Register(ctx, tailcfg.RegisterRequest{NodeKey: pair.nodeKey.Public(), Auth: &tailcfg.RegisterResponseAuth{AuthKey: token}, Hostinfo: &tailcfg.Hostinfo{Hostname: pair.n.Hostname}})
		if err != nil || !reply.MachineAuthorized {
			t.Fatalf("register %d: %v %#v", i, err, reply)
		}
	}
	ep := netip.MustParseAddrPort("203.0.113.7:41641")
	var disco key.DiscoPublic
	_ = disco.UnmarshalText([]byte(n2.DiscoKey))
	if _, err = c2.Map(ctx, tailcfg.MapRequest{NodeKey: k2.Public(), DiscoKey: disco, Endpoints: []netip.AddrPort{ep}, OmitPeers: true}); err != nil {
		t.Fatal(err)
	}
	response, err := c1.Map(ctx, tailcfg.MapRequest{NodeKey: k1.Public(), ReadOnly: true, Compress: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Peers) != 1 || response.Peers[0].Key != k2.Public() || !slices.Contains(response.Peers[0].Endpoints, ep) {
		t.Fatalf("peer map: %#v", response.Peers)
	}
	if response.Node.Addresses[0] == response.Peers[0].Addresses[0] {
		t.Fatal("duplicate address")
	}
	// The machine Noise identity, not merely possession of a public node key,
	// authorizes map fetches and rotation.
	if _, err = c2.Map(ctx, tailcfg.MapRequest{NodeKey: k1.Public(), ReadOnly: true}); err == nil {
		t.Fatal("another machine retrieved victim map")
	}
	// Reconnect to a different replica with the persisted server key. No sticky
	// sessions or coordinator process-local registration cache is necessary.
	c1.ServerURL = replicaHTTP.URL
	if _, err = c1.Map(ctx, tailcfg.MapRequest{NodeKey: k1.Public(), ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	rotated := key.NewNode()
	if _, err = c1.Register(ctx, tailcfg.RegisterRequest{NodeKey: rotated.Public(), OldNodeKey: k1.Public()}); err != nil {
		t.Fatal(err)
	}
	if _, err = c1.Map(ctx, tailcfg.MapRequest{NodeKey: k1.Public(), ReadOnly: true}); err == nil {
		t.Fatal("old rotated key still authorized")
	}
	if _, err = c1.Map(ctx, tailcfg.MapRequest{NodeKey: rotated.Public(), ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSingleUseClaimAndAddressAllocation(t *testing.T) {
	ctx := context.Background()
	store := &MemoryStore{}
	a, _ := newServer(t, store)
	b, _ := newServer(t, store)
	token, err := a.CreateInvitation(ctx, Invitation{Role: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, _, _ := testIdentity("worker")
			server := a
			if i%2 == 0 {
				server = b
			}
			err := server.Update(ctx, func(st *State) error {
				copy := n
				return claimInvitation(st, token, &copy)
			})
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("claim: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("single-use accepted %d times", success.Load())
	}
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _, _ := testIdentity("client")
			if err := b.Update(ctx, func(st *State) error { copy := n; return AllocateNode(st, &copy) }); err != nil {
				t.Errorf("seed: %v", err)
			}
		}()
	}
	wg.Wait()
	state, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ips := map[netip.Addr]bool{}
	ids := map[uint64]bool{}
	for _, n := range state.Nodes {
		if ids[n.ID] || ips[n.Addresses[0].Addr()] {
			t.Fatal("duplicate allocation after concurrent writes")
		}
		ids[n.ID] = true
		ips[n.Addresses[0].Addr()] = true
	}
	if len(state.Nodes) != 25 {
		t.Fatalf("lost updates: %d nodes", len(state.Nodes))
	}
}

func TestStreamRevocationClearsLastPeerAndPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store := &MemoryStore{}
	s, ts := newServer(t, store)
	other, _ := newServer(t, store)
	n, m, k := testIdentity("client")
	peer, _, _ := testIdentity("client")
	for _, node := range []Node{n, peer} {
		if err := s.Update(ctx, func(st *State) error { copy := node; return AllocateNode(st, &copy) }); err != nil {
			t.Fatal(err)
		}
	}
	client := &Client{ServerURL: ts.URL, MachineKey: m, ServerKey: s.PublicKey()}
	received := make(chan *tailcfg.MapResponse, 8)
	done := make(chan error, 1)
	go func() {
		done <- client.Stream(ctx, tailcfg.MapRequest{NodeKey: k.Public(), Compress: "zstd"}, func(msg *tailcfg.MapResponse) error { received <- msg; return nil })
	}()
	select {
	case msg := <-received:
		if len(msg.Peers) != 1 {
			t.Fatal("initial stream lacks peer")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := other.Update(ctx, func(st *State) error {
		st.Nodes[peer.MachineKey].Revoked = true
		st.Policy = []tailcfg.FilterRule{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-received:
		if msg.Peers == nil || len(msg.Peers) != 0 || msg.PacketFilter == nil || len(msg.PacketFilter) != 0 {
			t.Fatalf("empty updates omitted, leaves stale access: %#v", msg)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := other.Update(ctx, func(st *State) error { st.Nodes[n.MachineKey].Revoked = true; return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked stream returned no error")
		}
	case <-ctx.Done():
		t.Fatal("revocation did not terminate map stream")
	}
}

func TestGatewayElectionAndUnapprovedRoutes(t *testing.T) {
	st := NewState()
	client, _, _ := testIdentity("client")
	a, _, _ := testIdentity("hub")
	b, _, _ := testIdentity("hub")
	route := netip.MustParsePrefix("10.42.0.0/16")
	unapproved := netip.MustParsePrefix("0.0.0.0/0")
	for _, n := range []*Node{&client, &a, &b} {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route, unapproved}}
		if n.Role == "hub" {
			n.ApprovedRoutes = []netip.Prefix{route}
		}
		if err := AllocateNode(st, n); err != nil {
			t.Fatal(err)
		}
	}
	check := func(winner uint64) {
		t.Helper()
		response, err := MapForState(st, client.MachineKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range response.Peers {
			if slices.Contains(peer.AllowedIPs, unapproved) {
				t.Fatal("unapproved Internet route distributed")
			}
			if got := slices.Contains(peer.AllowedIPs, route); got != (uint64(peer.ID) == winner) {
				t.Fatalf("route owner %d, expected %d", peer.ID, winner)
			}
		}
	}
	check(a.ID)
	st.Nodes[a.MachineKey].LastSeen = time.Now().Add(-2 * time.Minute)
	check(b.ID)
	st.Nodes[b.MachineKey].Revoked = true
	check(0)
}

func TestMapForStatePreservesLocalRoutesAndFiltersInactiveRouters(t *testing.T) {
	st := NewState()
	st.Domain = "private.example"
	shared := netip.MustParsePrefix("10.42.0.0/16")
	remote := netip.MustParsePrefix("10.43.0.0/16")
	unadvertised := netip.MustParsePrefix("10.44.0.0/16")
	expired, _, _ := testIdentity("hub")
	stale, _, _ := testIdentity("hub")
	primary, _, _ := testIdentity("hub")
	self, _, _ := testIdentity("worker")
	for _, n := range []*Node{&expired, &stale, &primary, &self} {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{shared, remote}}
		n.ApprovedRoutes = []netip.Prefix{shared, remote, unadvertised}
		if err := AllocateNode(st, n); err != nil {
			t.Fatal(err)
		}
	}
	st.Nodes[expired.MachineKey].KeyExpiry = time.Now().Add(-time.Minute)
	st.Nodes[stale.MachineKey].LastSeen = time.Now().Add(-2 * time.Minute)
	st.Nodes[self.MachineKey].Hostinfo.RoutableIPs = []netip.Prefix{shared}
	msg, err := MapForState(st, self.MachineKey)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Node == nil || uint64(msg.Node.ID) != self.ID || len(msg.Peers) != 2 {
		t.Fatalf("self or active peer membership changed: %#v", msg)
	}
	if uint64(msg.Peers[0].ID) != stale.ID || uint64(msg.Peers[1].ID) != primary.ID {
		t.Fatal("peers are not ordered by stable node ID")
	}
	if len(msg.Peers[0].PrimaryRoutes) != 0 || !slices.Equal(msg.Peers[1].PrimaryRoutes, []netip.Prefix{remote}) {
		t.Fatalf("route election/local exclusion: stale=%v, primary=%v", msg.Peers[0].PrimaryRoutes, msg.Peers[1].PrimaryRoutes)
	}
	for _, n := range append(msg.Peers, msg.Node) {
		if slices.Contains(n.AllowedIPs, shared) || slices.Contains(n.AllowedIPs, unadvertised) {
			t.Fatalf("local or unadvertised route distributed to %d: %v", n.ID, n.AllowedIPs)
		}
		if !strings.HasSuffix(n.Name, ".private.example.") {
			t.Fatalf("wrong domain: %s", n.Name)
		}
	}
	// When this worker wins the route, its own map must retain the route.
	st.Nodes[primary.MachineKey].Revoked = true
	msg, err = MapForState(st, self.MachineKey)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(msg.Node.PrimaryRoutes, []netip.Prefix{shared}) || !slices.Contains(msg.Node.AllowedIPs, shared) {
		t.Fatalf("winning local route omitted: %#v", msg.Node)
	}
}

func TestUnauthorizedHTTPAndMalformedRequests(t *testing.T) {
	s, _ := newServer(t, &MemoryStore{})
	for _, path := range []string{"/machine/map", "/machine/register", "/api/v1/nodes"} {
		req := httptest.NewRequest("POST", path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: got %d", path, w.Code)
		}
	}
	req := httptest.NewRequest("GET", "/key?v=1", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	var keys tailcfg.OverTLSPublicKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &keys); err != nil || keys.PublicKey != s.PublicKey() {
		t.Fatal("incorrect public Noise key")
	}
}

func TestReadinessRequiresDurableNetworkState(t *testing.T) {
	store := &MemoryStore{}
	s, _ := newServer(t, store)
	ready := func() int {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		return w.Code
	}
	if got := ready(); got != http.StatusServiceUnavailable {
		t.Fatalf("empty registry readiness=%d", got)
	}
	n, _, _ := testIdentity("hub")
	if err := s.Update(context.Background(), func(st *State) error { copy := n; return AllocateNode(st, &copy) }); err != nil {
		t.Fatal(err)
	}
	if got := ready(); got != http.StatusOK {
		t.Fatalf("initialized readiness=%d", got)
	}
	store.mu.Lock()
	store.state = nil
	store.mu.Unlock()
	if got := ready(); got != http.StatusServiceUnavailable {
		t.Fatalf("lost registry readiness=%d", got)
	}
}

func TestLongKubernetesHostnamePreserved(t *testing.T) {
	st := NewState()
	n, _, _ := testIdentity("worker")
	n.Hostname = strings.Repeat("h", 63)
	if err := AllocateNode(st, &n); err != nil {
		t.Fatal(err)
	}
	if n.Hostname != strings.Repeat("h", 63) {
		t.Fatal("enrollment identity truncated to a different Kubernetes node name")
	}
	native := n.TailNode()
	if native.Hostinfo.Hostname() != n.Hostname {
		t.Fatal("map must carry original hostname independently of unique DNS label")
	}
	label, _, _ := strings.Cut(native.Name, ".")
	if len(label) > 63 {
		t.Fatal("map DNS label exceeds 63 octets")
	}
}
