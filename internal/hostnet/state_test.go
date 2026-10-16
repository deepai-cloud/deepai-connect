package hostnet

import (
	"encoding/json"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func testState(t *testing.T, number uint8) (*State, *Identity) {
	t.Helper()
	id := &Identity{Machine: key.NewMachine(), Node: key.NewNode()}
	id.Disco = discoveryKey(id.Node)
	address := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, number}), 32)
	now := time.Now()
	s := &State{Version: StateVersion, ClusterID: "test-cluster", Self: &tailcfg.Node{ID: tailcfg.NodeID(number), Key: id.Node.Public(), Machine: id.Machine.Public(), DiscoKey: id.Disco.Public(), Addresses: []netip.Prefix{address}, AllowedIPs: []netip.Prefix{address}}, HostCIDR: netip.MustParsePrefix("100.64.0.0/10"), PodCIDR: netip.MustParsePrefix("10.42.0.0/16"), ServiceCIDR: netip.MustParsePrefix("10.43.0.0/16"), Interface: DefaultInterface, ListenPort: DefaultPort, UpdatedAt: now, ExpiresAt: now.Add(CacheLifetime), DirectHubEndpoints: make(map[key.NodePublic][]netip.AddrPort)}
	s.PacketFilter = []tailcfg.FilterRule{{SrcIPs: []string{s.HostCIDR.String()}, DstPorts: []tailcfg.NetPortRange{{IP: s.HostCIDR.String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}}}}}
	return s, id
}

func TestEgressDisablePrunesCachedAuthorityWithoutRenewingTrust(t *testing.T) {
	s, id := testState(t, 1)
	peer, _ := testState(t, 2)
	def := netip.MustParsePrefix("0.0.0.0/0")
	pod := netip.MustParsePrefix("10.42.2.0/24")
	s.EgressSources = slices.Clone(s.Self.Addresses)
	s.ApprovedRoutes = []netip.Prefix{def}
	s.Self.AllowedIPs = append(s.Self.AllowedIPs, def)
	s.Self.PrimaryRoutes = []netip.Prefix{def}
	s.Self.Hostinfo = (&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{def, pod}}).View()
	peer.Self.AllowedIPs = append(peer.Self.AllowedIPs, def, pod, netip.MustParsePrefix("203.0.113.0/24"))
	peer.Self.PrimaryRoutes = []netip.Prefix{def, pod}
	s.Peers = []*tailcfg.Node{peer.Self}
	before, _ := json.Marshal(s)
	disabled := s.WithEgressConfig(nil, false)
	if err := disabled.Validate(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(disabled.EgressSources) != 0 || len(disabled.ApprovedRoutes) != 0 || !disabled.UpdatedAt.Equal(s.UpdatedAt) || !disabled.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("disable changed trust or retained opt-in")
	}
	for _, n := range append([]*tailcfg.Node{disabled.Self}, disabled.Peers...) {
		if slices.Contains(n.AllowedIPs, def) || slices.Contains(n.PrimaryRoutes, def) {
			t.Fatal("cached default survived disable")
		}
	}
	if !slices.Contains(disabled.Peers[0].AllowedIPs, pod) || len(disabled.Peers[0].AllowedIPs) != 2 {
		t.Fatal("disable did not preserve private route or prune implicit public authority")
	}
	if slices.Contains(disabled.Self.Hostinfo.AsStruct().RoutableIPs, def) {
		t.Fatal("disabled gateway advertises default")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("normalization mutated the live input")
	}
	dir := t.TempDir()
	if err := SaveState(dir, disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatal("disabled cache cannot recover offline:", err)
	}
}

func TestExpiredPeerDoesNotBlockHubRecovery(t *testing.T) {
	s, id := testState(t, 1)
	expired, _ := testState(t, 2)
	alive, _ := testState(t, 3)
	expired.Self.KeyExpiry = time.Now().Add(-time.Second)
	s.Peers = []*tailcfg.Node{expired.Self, alive.Self}
	s.DirectHubEndpoints[expired.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:41641")}
	s.DirectHubEndpoints[alive.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.3:41641")}
	dir := t.TempDir()
	// Represents a formerly valid snapshot whose peer expired while powered off.
	write := func(state *State) {
		t.Helper()
		b, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err = platform.WriteFile(filepath.Join(dir, "overlay.json"), b, false); err != nil {
			t.Fatal(err)
		}
	}
	write(s)
	restored, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Peers) != 1 || restored.Peers[0].Key != alive.Self.Key || len(restored.DirectHubEndpoints[expired.Self.Key]) != 0 {
		t.Fatal("expired peer authority or endpoints survived recovery")
	}
	if !restored.ExpiresAt.Equal(s.ExpiresAt) || !restored.UpdatedAt.Equal(s.UpdatedAt) {
		t.Fatal("peer pruning renewed trusted cache validity")
	}
	if err := restored.Validate(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Self.KeyExpiry = time.Now().Add(-time.Second)
	write(s)
	if _, err := LoadState(dir); err == nil {
		t.Fatal("expired local key was accepted")
	}
	s.Self = nil
	write(s)
	if _, err := LoadState(dir); err == nil {
		t.Fatal("missing local identity was accepted")
	}
}

func TestIdentityPrivateAndStable(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Node.Public() != b.Node.Public() || a.Machine.Public() != b.Machine.Public() || a.Disco.Public() != b.Disco.Public() {
		t.Fatal("restart changed device keys")
	}
	fi, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("identity permissions %v", fi.Mode())
	}
}

func TestStateRejectsUntrustedCache(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*State)
	}{
		{"expired", func(s *State) { s.ExpiresAt = time.Now().Add(-time.Minute) }},
		{"overlap", func(s *State) { s.PodCIDR = s.HostCIDR }},
		{"impersonation", func(s *State) {
			p, _ := testState(t, 2)
			p.Self.AllowedIPs = append(p.Self.AllowedIPs, s.HostCIDR)
			s.Peers = []*tailcfg.Node{p.Self}
		}},
		{"unapproved route", func(s *State) { s.Self.AllowedIPs = append(s.Self.AllowedIPs, netip.MustParsePrefix("192.168.0.0/16")) }},
		{"key mismatch", func(s *State) { s.Self.Key = key.NewNode().Public() }},
		{"insecure coordinator", func(s *State) { s.CoordinatorURL = "http://example.com" }},
		{"unknown cached hub", func(s *State) {
			s.DirectHubEndpoints[key.NewNode().Public()] = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:41641")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, id := testState(t, 1)
			tc.edit(s)
			if err := s.Validate(id, time.Now()); err == nil {
				t.Fatal("accepted invalid state")
			}
		})
	}
}

func TestRevocationRemovesCachedEndpoints(t *testing.T) {
	s, id := testState(t, 1)
	p, _ := testState(t, 2)
	s.Peers = []*tailcfg.Node{p.Self}
	s.DirectHubEndpoints[p.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}
	n, err := s.WithMap(&tailcfg.MapResponse{Node: s.Self, Peers: []*tailcfg.Node{}, PacketFilter: s.PacketFilter}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Validate(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(n.Peers) != 0 || len(n.DirectHubEndpoints) != 0 {
		t.Fatal("revoked peer survived in offline cache")
	}
	dir := t.TempDir()
	if err := SaveState(dir, n); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Peers) != 0 {
		t.Fatal("revoked peer restored")
	}
}

func TestLocalPodRoutesValidateAndSurviveCoordinatorRefresh(t *testing.T) {
	s, id := testState(t, 2)
	s.PodRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}
	if err := s.Validate(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	n, err := s.WithMap(&tailcfg.MapResponse{Node: s.Self, Peers: []*tailcfg.Node{}, PacketFilter: s.PacketFilter}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(n.PodRoutes, s.PodRoutes) {
		t.Fatal("coordinator map discarded the local Kubernetes pod assignment")
	}
	if slices.Contains(n.Self.AllowedIPs, s.PodRoutes[0]) {
		t.Fatal("local advertisement implicitly authorized an unapproved source prefix")
	}
	dir := t.TempDir()
	if err := SaveState(dir, n); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(restored.PodRoutes, s.PodRoutes) {
		t.Fatal("pod routes were not persisted for restart")
	}
	for _, routes := range [][]netip.Prefix{
		{netip.MustParsePrefix("10.43.2.0/24")},
		{netip.MustParsePrefix("10.42.2.1/24")},
		{netip.MustParsePrefix("10.0.0.0/8")},
		{netip.MustParsePrefix("10.42.2.0/24"), netip.MustParsePrefix("10.42.2.128/25")},
	} {
		bad := s.Clone()
		bad.PodRoutes = routes
		if err := bad.Validate(id, time.Now()); err == nil {
			t.Fatalf("accepted invalid local pod routes %v", routes)
		}
	}
}
