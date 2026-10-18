package hostnet

import (
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
)

// transportState publishes the trusted snapshot and its routing indexes in one
// atomic operation. Packet lookups must not allocate or scan the entire mesh.
// All fields are immutable after publication.
type transportState struct {
	*State
	routes bart.Table[wgengine.PeerForIP]
	peers  map[key.NodePublic]peerRoutes
}

type peerRoutes struct {
	node   *tailcfg.Node
	routes []netip.Prefix
}

func newTransportState(s *State) *transportState {
	out := &transportState{State: s, peers: make(map[key.NodePublic]peerRoutes, len(s.Peers))}
	add := func(n *tailcfg.Node, self bool) {
		routes := nodeRoutes(n)
		if !self {
			out.peers[n.Key] = peerRoutes{node: n, routes: routes}
		}
		for _, p := range routes {
			// Preserve the existing tie-break: self wins equal prefixes, then
			// the first peer in the coordinator map. More-specific routes win
			// independently of that order.
			if _, exists := out.routes.Get(p); !exists {
				out.routes.Insert(p, wgengine.PeerForIP{Node: n.View(), IsSelf: self, Route: p})
			}
		}
	}
	add(s.Self, true)
	for _, peer := range s.Peers {
		add(peer, false)
	}
	return out
}

func (t *transport) peerConfig(k key.NodePublic) ([]netip.Prefix, bool) {
	s := t.state.Load()
	if s == nil {
		return nil, false
	}
	p, ok := s.peers[k]
	// WireGuard owns the returned slice; the published index stays immutable.
	return slices.Clone(p.routes), ok
}

func (t *transport) peerForIP(ip netip.Addr) (wgengine.PeerForIP, bool) {
	s := t.state.Load()
	if s == nil || ip.Zone() != "" {
		return wgengine.PeerForIP{}, false
	}
	return s.routes.Lookup(ip)
}
