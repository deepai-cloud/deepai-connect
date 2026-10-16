package hostnet

import (
	"encoding/json"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
)

func TestRecursiveEndpointSanitization(t *testing.T) {
	s, _ := testState(t, 1)
	peer, _ := testState(t, 2)
	peer.Self.Tags = []string{"tag:hub"}
	var candidates []netip.AddrPort
	for _, text := range []string{"100.64.0.2:41641", "10.42.0.1:41641", "10.43.0.10:41641", "[::ffff:10.42.0.1]:41641", "203.0.113.2:41641", "192.168.64.3:41641", "[2001:db8::1]:41641", "[::ffff:203.0.113.2]:41641"} {
		candidates = append(candidates, netip.MustParseAddrPort(text))
	}
	want := candidates[4:7]
	s.Self.Endpoints, peer.Self.Endpoints = slices.Clone(candidates), slices.Clone(candidates)
	s.Peers = []*tailcfg.Node{peer.Self}
	s.DirectHubEndpoints[s.Self.Key] = slices.Clone(candidates)
	s.DirectHubEndpoints[peer.Self.Key] = slices.Clone(candidates)
	assert := func(got *State) {
		t.Helper()
		for _, endpoints := range [][]netip.AddrPort{got.Self.Endpoints, got.Peers[0].Endpoints, got.DirectHubEndpoints[got.Self.Key], got.DirectHubEndpoints[peer.Self.Key]} {
			if !slices.Equal(endpoints, want) {
				t.Fatalf("underlay candidates = %v; want %v", endpoints, want)
			}
		}
	}
	// Model a cache written before the bug was fixed, without extending its
	// existing trust window merely because recursive candidates are pruned.
	dir := t.TempDir()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFile(filepath.Join(dir, "overlay.json"), b, false); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	assert(restored)
	if !restored.UpdatedAt.Equal(s.UpdatedAt) || !restored.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("endpoint sanitation renewed cached trust")
	}
	if err := SaveState(dir, s); err != nil {
		t.Fatal(err)
	}
	b, err = platform.ReadFile(filepath.Join(dir, "overlay.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved State
	if err := json.Unmarshal(b, &saved); err != nil {
		t.Fatal(err)
	}
	assert(&saved)
	mapped, err := s.WithMap(&tailcfg.MapResponse{Node: s.Self, Peers: s.Peers, PacketFilter: s.PacketFilter}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	assert(mapped)
	if !slices.Equal(s.Self.Endpoints, candidates) {
		t.Fatal("sanitation mutated caller-owned state")
	}
	tr := &transport{endpoints: candidates}
	tr.state.Store(s)
	if got := tr.Endpoints(); !slices.Equal(got, want) {
		t.Fatalf("live publication escaped sanitation: %v", got)
	}
}

func TestDiscoveryExcludesOnlyClusterAddresses(t *testing.T) {
	s, _ := testState(t, 1)
	address := func(text string) net.Addr {
		t.Helper()
		ip, network, err := net.ParseCIDR(text)
		if err != nil {
			t.Fatal(err)
		}
		network.IP = ip
		return network
	}
	lan, public := address("192.168.64.3/24"), address("203.0.113.2/24")
	cni, overlay, service := address("10.42.0.1/24"), address("100.64.0.1/32"), address("10.43.0.10/32")
	got := underlayInterfaceAddresses([]net.Addr{cni, lan, overlay, public, service}, s.endpointRanges())
	if len(got) != 2 || got[0] != lan || got[1] != public {
		t.Fatalf("discovery altered valid underlay addresses: %v", got)
	}
	// Exercise upstream's AltAddrs semantics: an empty CNI interface must not
	// silently fall back to the operating system's actual interface addresses.
	empty := underlayInterfaceAddresses([]net.Addr{cni, overlay, service}, s.endpointRanges())
	if empty == nil {
		t.Fatal("nil permits upstream discovery to reread excluded addresses")
	}
	iface := netmon.Interface{Interface: &net.Interface{Index: -1}, AltAddrs: empty}
	if addrs, err := iface.Addrs(); err != nil || len(addrs) != 0 {
		t.Fatalf("upstream rediscovered excluded interface addresses: %v %v", addrs, err)
	}
}
