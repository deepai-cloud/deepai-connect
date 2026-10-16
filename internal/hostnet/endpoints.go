package hostnet

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
)

type endpointRanges [3]netip.Prefix

func (s *State) endpointRanges() endpointRanges {
	return endpointRanges{s.HostCIDR, s.PodCIDR, s.ServiceCIDR}
}

func (ranges endpointRanges) contains(ip netip.Addr) bool {
	for _, prefix := range ranges {
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// UnderlayEndpoints excludes destinations whose reachability depends on the
// tunnel itself. In particular, a remote CNI bridge may answer disco through
// Flannel, then blackhole WireGuard when selected as the tunnel's endpoint.
// RFC1918 LAN and public NAT candidates remain valid underlay paths.
func (s *State) UnderlayEndpoints(endpoints []netip.AddrPort) []netip.AddrPort {
	ranges := s.endpointRanges()
	var out []netip.AddrPort
	for _, ep := range endpoints {
		if validEndpoint(ep) && !ranges.contains(ep.Addr()) {
			ep = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
			if !slices.Contains(out, ep) {
				out = append(out, ep)
			}
		}
	}
	return out
}

func (s *State) pruneRecursiveEndpoints() {
	for _, node := range append([]*tailcfg.Node{s.Self}, s.Peers...) {
		if node != nil {
			node.Endpoints = s.UnderlayEndpoints(node.Endpoints)
		}
	}
	for key, endpoints := range s.DirectHubEndpoints {
		s.DirectHubEndpoints[key] = s.UnderlayEndpoints(endpoints)
	}
}

var discoveryRanges atomic.Pointer[endpointRanges]

func init() {
	// Upstream's getter registration is unsynchronized. Install the adapter
	// once, before any monitor or engine goroutines exist; its configuration is
	// an atomic immutable value. In-memory transports never configure it.
	netmon.RegisterInterfaceGetter(underlayInterfaces)
}

func configureEndpointDiscovery(s *State) error {
	ranges := s.endpointRanges()
	if discoveryRanges.CompareAndSwap(nil, &ranges) {
		return nil
	}
	if *discoveryRanges.Load() != ranges {
		return errors.New("host process already owns another overlay's discovery ranges")
	}
	return nil
}

func underlayInterfaces() ([]netmon.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ranges := discoveryRanges.Load()
	out := make([]netmon.Interface, len(ifs))
	for i := range ifs {
		out[i].Interface = &ifs[i]
		if ranges == nil {
			continue
		}
		addresses, err := ifs[i].Addrs()
		if err != nil {
			return nil, err
		}
		out[i].AltAddrs = underlayInterfaceAddresses(addresses, *ranges)
	}
	return out, nil
}

func underlayInterfaceAddresses(addresses []net.Addr, ranges endpointRanges) []net.Addr {
	// Non-nil empty means no addresses; nil would make netmon fall back to the
	// real interface and advertise the excluded CNI/overlay addresses again.
	out := make([]net.Addr, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && ranges.contains(prefix.Addr()) {
			continue
		}
		out = append(out, address)
	}
	return out
}
