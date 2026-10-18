package hostnet

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func benchmarkState(peers int) *State {
	now := time.Now()
	s := &State{Version: StateVersion, ClusterID: "benchmark", HostCIDR: netip.MustParsePrefix("100.64.0.0/10"), PodCIDR: netip.MustParsePrefix("10.42.0.0/16"), ServiceCIDR: netip.MustParsePrefix("10.43.0.0/16"), UpdatedAt: now, ExpiresAt: now.Add(CacheLifetime), PacketFilter: tailcfg.FilterAllowAll, DirectHubEndpoints: make(map[key.NodePublic][]netip.AddrPort)}
	for i := 0; i <= peers; i++ {
		addr := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}), 32)
		pod := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 42, byte(i), 0}), 24)
		n := &tailcfg.Node{ID: tailcfg.NodeID(i + 1), Key: key.NewNode().Public(), Addresses: []netip.Prefix{addr}, AllowedIPs: []netip.Prefix{addr, pod}, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}, Hostinfo: (&tailcfg.Hostinfo{Hostname: fmt.Sprintf("worker-%d", i)}).View()}
		if i == 0 {
			s.Self = n
		} else {
			s.Peers = append(s.Peers, n)
		}
		s.DirectHubEndpoints[n.Key] = n.Endpoints
	}
	return s
}

func BenchmarkStateClone(b *testing.B) {
	for _, peers := range []int{4, 64, 256} {
		b.Run(fmt.Sprintf("peers_%d", peers), func(b *testing.B) {
			s := benchmarkState(peers)
			b.ReportAllocs()
			for b.Loop() {
				_ = s.Clone()
			}
		})
	}
}

func BenchmarkPeerForIP(b *testing.B) {
	for _, peers := range []int{4, 64, 256} {
		b.Run(fmt.Sprintf("peers_%d", peers), func(b *testing.B) {
			s := benchmarkState(peers)
			tr := new(transport)
			tr.state.Store(newTransportState(s))
			ip := s.Peers[len(s.Peers)-1].Addresses[0].Addr()
			b.ReportAllocs()
			for b.Loop() {
				_, _ = tr.peerForIP(ip)
			}
		})
	}
}

// Include the one-time routing-index construction in the cost of accepting a
// new map, so packet lookup gains are measured alongside their setup cost.
func BenchmarkTransportState(b *testing.B) {
	for _, peers := range []int{4, 64, 256} {
		b.Run(fmt.Sprintf("peers_%d", peers), func(b *testing.B) {
			s := benchmarkState(peers)
			b.ReportAllocs()
			for b.Loop() {
				_ = newTransportState(s.Clone())
			}
		})
	}
}
