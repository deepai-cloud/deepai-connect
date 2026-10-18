package coordinator

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func benchmarkMapState(nodes, routes int) (*State, string) {
	st := NewState()
	var machine string
	for i := 0; i < nodes; i++ {
		n, _, _ := testIdentity("worker")
		n.ID = uint64(i + 1)
		n.Created = time.Now().UTC()
		n.LastSeen = n.Created
		n.Addresses = []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte((i + 1) >> 8), byte(i + 1)}), 32)}
		n.Hostinfo = &tailcfg.Hostinfo{Hostname: "worker"}
		for j := 0; j < routes; j++ {
			route := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(j), 0, 0}), 16)
			n.ApprovedRoutes = append(n.ApprovedRoutes, route)
			n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, route)
		}
		st.Nodes[n.MachineKey] = &n
		machine = n.MachineKey
	}
	return st, machine
}

func BenchmarkMapForState(b *testing.B) {
	for _, nodes := range []int{10, 100, 1000} {
		for _, routes := range []int{0, 8} {
			b.Run(fmt.Sprintf("nodes=%d/routes=%d", nodes, routes), func(b *testing.B) {
				st, machine := benchmarkMapState(nodes, routes)
				b.ReportAllocs()
				for b.Loop() {
					if _, err := MapForState(st, machine); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
