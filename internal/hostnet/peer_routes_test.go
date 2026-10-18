package hostnet

import (
	"net/netip"
	"slices"
	"sync"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
)

func TestPeerLookupPreservesRouteSelection(t *testing.T) {
	s, _ := testState(t, 1)
	a, _ := testState(t, 2)
	b, _ := testState(t, 3)
	s.Peers = []*tailcfg.Node{a.Self, b.Self}
	s.Self.AllowedIPs = append(s.Self.AllowedIPs, netip.MustParsePrefix("10.42.1.0/24"))
	a.Self.AllowedIPs = append(a.Self.AllowedIPs,
		netip.MustParsePrefix("10.42.0.0/16"),
		netip.MustParsePrefix("10.42.1.0/24"),
		netip.MustParsePrefix("10.42.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::ffff:192.0.2.0/120"))
	b.Self.AllowedIPs = append(b.Self.AllowedIPs,
		netip.MustParsePrefix("10.42.2.0/24"),
		netip.MustParsePrefix("10.42.2.128/25"),
		netip.MustParsePrefix("2001:db8:1::/48"))
	// Addresses remain reachable even when omitted from AllowedIPs.
	b.Self.AllowedIPs = b.Self.AllowedIPs[1:]
	tr := new(transport)
	if _, ok := tr.peerForIP(netip.MustParseAddr("100.64.0.2")); ok {
		t.Fatal("uninitialized transport returned a peer")
	}
	for _, defaults := range []bool{false, true} {
		if defaults {
			b.Self.AllowedIPs = append(b.Self.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
		}
		tr.state.Store(newTransportState(s))
		addresses := []netip.Addr{{}, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("2001:db8::1%eth0")}
		for i := range 256 {
			addresses = append(addresses, netip.AddrFrom4([4]byte{100, 64, 0, byte(i)}), netip.AddrFrom4([4]byte{10, 42, byte(i), 1}), netip.AddrFrom4([4]byte{10, 42, 2, byte(i)}))
		}
		for _, ip := range addresses {
			got, ok := tr.peerForIP(ip)
			want, wantOK := linearPeerForIP(s, ip)
			if ok != wantOK || (ok && (got.Node.Key() != want.Node.Key() || got.Route != want.Route || got.IsSelf != want.IsSelf)) {
				t.Fatalf("lookup %v (defaults=%v): got %v/%v, want %v/%v", ip, defaults, got, ok, want, wantOK)
			}
		}
	}
}

// The original route-selection algorithm is an oracle for prefix precedence,
// family handling, self routes and equal-prefix ordering.
func linearPeerForIP(s *State, ip netip.Addr) (wgengine.PeerForIP, bool) {
	var best wgengine.PeerForIP
	found, bits := false, -1
	for _, n := range append([]*tailcfg.Node{s.Self}, s.Peers...) {
		for _, p := range nodeRoutes(n) {
			if p.Contains(ip) && p.Bits() > bits {
				found, bits = true, p.Bits()
				best = wgengine.PeerForIP{Node: n.View(), IsSelf: n.Key == s.Self.Key, Route: p}
			}
		}
	}
	return best, found
}

func TestPeerIndexReplacementRevokesRoutes(t *testing.T) {
	s, _ := testState(t, 1)
	peer, _ := testState(t, 2)
	s.Peers = []*tailcfg.Node{peer.Self}
	tr := new(transport)
	if _, ok := tr.peerConfig(peer.Self.Key); ok {
		t.Fatal("uninitialized transport returned a peer config")
	}
	tr.state.Store(newTransportState(s))
	routes, ok := tr.peerConfig(peer.Self.Key)
	if !ok || !slices.Equal(routes, peer.Self.AllowedIPs) {
		t.Fatal("peer config lost approved routes")
	}
	routes[0] = netip.MustParsePrefix("0.0.0.0/0")
	routes, _ = tr.peerConfig(peer.Self.Key)
	if !slices.Equal(routes, peer.Self.AllowedIPs) {
		t.Fatal("caller can mutate the published route index")
	}
	if _, ok := tr.peerConfig(key.NewNode().Public()); ok {
		t.Fatal("unknown peer acquired routing authority")
	}
	next := s.Clone()
	next.Peers = nil
	tr.state.Store(newTransportState(next))
	if _, ok := tr.peerConfig(peer.Self.Key); ok {
		t.Fatal("revoked peer retained WireGuard configuration")
	}
	if _, ok := tr.peerForIP(peer.Self.Addresses[0].Addr()); ok {
		t.Fatal("revoked peer retained destination route")
	}
}

func TestPeerLookupDuringSnapshotReplacement(t *testing.T) {
	s, _ := testState(t, 1)
	peer, _ := testState(t, 2)
	s.Peers = []*tailcfg.Node{peer.Self}
	next := s.Clone()
	next.Peers[0].AllowedIPs = append(next.Peers[0].AllowedIPs, netip.MustParsePrefix("10.42.0.0/16"))
	snapshots := []*transportState{newTransportState(s), newTransportState(next)}
	tr := new(transport)
	tr.state.Store(snapshots[0])
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				got, ok := tr.peerForIP(peer.Self.Addresses[0].Addr())
				if !ok || got.Node.Key() != peer.Self.Key {
					t.Error("snapshot replacement lost a stable peer")
					return
				}
				tr.peerConfig(peer.Self.Key)
			}
		})
	}
	for i := range 1000 {
		tr.state.Store(snapshots[i%len(snapshots)])
	}
	wg.Wait()
}
