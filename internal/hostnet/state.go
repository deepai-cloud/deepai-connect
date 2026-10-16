// Package hostnet owns the single host overlay during bootstrap, recovery and
// normal operation. It deliberately has no Kubernetes dependency.
package hostnet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

const StateVersion = 1
const DefaultInterface = "deepai0"
const DefaultPort = 41641
const CacheLifetime = 30 * 24 * time.Hour

// Identity never leaves the host. Persisting the discovery key is intentional:
// simultaneously restarting hubs must be able to use each other's cached keys
// before the coordinator and DERP come back.
type Identity struct {
	Machine key.MachinePrivate
	Node    key.NodePrivate
	Disco   key.DiscoPrivate `json:"-"`
}

// Upstream deliberately has no DiscoPrivate serialization API. Derive the
// restart-stable discovery secret with domain separation from the locally
// stored node private key instead of depending on its unexported layout.
func discoveryKey(node key.NodePrivate) key.DiscoPrivate {
	raw := node.Raw32()
	h := hmac.New(sha256.New, raw[:])
	_, _ = h.Write([]byte("deepai-connect/discovery-key/v1"))
	b := h.Sum(nil)
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return key.DiscoPrivateFromRaw32(mem.B(b))
}

func (id *Identity) UnmarshalJSON(b []byte) error {
	type diskIdentity Identity
	var disk diskIdentity
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	*id = Identity(disk)
	if !id.Node.IsZero() {
		id.Disco = discoveryKey(id.Node)
	}
	return nil
}

func LoadOrCreateIdentity(dir string) (*Identity, error) {
	path := filepath.Join(dir, "identity.json")
	b, err := platform.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id := &Identity{Machine: key.NewMachine(), Node: key.NewNode()}
		id.Disco = discoveryKey(id.Node)
		b, err = json.Marshal(id)
		if err != nil {
			return nil, err
		}
		if err = platform.WriteFile(path, b, true); err != nil {
			if errors.Is(err, os.ErrExist) {
				return LoadOrCreateIdentity(dir)
			}
			return nil, err
		}
		return id, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeIdentity(b)
}

// LoadIdentity is the steady-state path. A missing enrolled device key must
// require explicit recovery, never silently create a replacement identity.
func LoadIdentity(dir string) (*Identity, error) {
	b, err := platform.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, fmt.Errorf("load existing host identity: %w", err)
	}
	return decodeIdentity(b)
}

func decodeIdentity(b []byte) (*Identity, error) {
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, err
	}
	if id.Machine.IsZero() || id.Node.IsZero() || id.Disco.IsZero() {
		return nil, errors.New("incomplete host identity")
	}
	return &id, nil
}

// State contains only public network identity and approved policy. It is the
// durable, trusted control-plane snapshot, not a second bootstrap network.
type State struct {
	Version        int
	ClusterID      string
	CoordinatorURL string
	Self           *tailcfg.Node
	Peers          []*tailcfg.Node
	DERPMap        *tailcfg.DERPMap
	PacketFilter   []tailcfg.FilterRule
	HostCIDR       netip.Prefix
	PodCIDR        netip.Prefix
	ServiceCIDR    netip.Prefix
	// PodRoutes are this node's Kubernetes-assigned pod prefixes. They are
	// advertised for approval so WireGuard can authenticate pod source IPs;
	// they do not grant routing permission before the coordinator approves them.
	PodRoutes []netip.Prefix
	// ApprovedRoutes is the local opt-in to additional subnet routes. Pod and
	// service prefixes are implicit opt-ins; default routes are never implicit.
	ApprovedRoutes []netip.Prefix
	// EgressSources explicitly opts these pod prefixes or this host's overlay
	// /32 into Internet routing. Host control traffic keeps its physical source.
	EgressSources      []netip.Prefix
	DirectHubEndpoints map[key.NodePublic][]netip.AddrPort
	ListenPort         uint16
	Interface          string
	UpdatedAt          time.Time
	ExpiresAt          time.Time
}

func (s *State) Clone() *State {
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return &out
}

func (s *State) Validate(id *Identity, now time.Time) error {
	if s == nil || s.Version != StateVersion || s.ClusterID == "" {
		return errors.New("invalid overlay state version or cluster identity")
	}
	if s.Self == nil || s.Self.Key.IsZero() || len(s.Self.Addresses) == 0 {
		return errors.New("overlay state has no local identity/address")
	}
	if id != nil && (s.Self.Key != id.Node.Public() || s.Self.DiscoKey != id.Disco.Public() || s.Self.Machine != id.Machine.Public()) {
		return errors.New("overlay state does not match the local identity")
	}
	if s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt) || s.UpdatedAt.After(now.Add(5*time.Minute)) || s.ExpiresAt.Sub(s.UpdatedAt) > CacheLifetime {
		return errors.New("overlay cache is expired or has invalid validity bounds; run deepai-connect refresh with a trusted coordinator")
	}
	if s.Interface == "" {
		s.Interface = DefaultInterface
	}
	if len(s.Interface) > 15 {
		return errors.New("overlay interface name exceeds 15 characters")
	}
	for _, r := range s.Interface {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return errors.New("invalid overlay interface name")
		}
	}
	if s.ListenPort == 0 {
		s.ListenPort = DefaultPort
	}
	if s.CoordinatorURL != "" {
		u, err := url.Parse(s.CoordinatorURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("coordinator must use an authenticated HTTPS endpoint")
		}
	}
	spaces := []netip.Prefix{s.HostCIDR, s.PodCIDR, s.ServiceCIDR}
	for i, p := range spaces {
		if !p.IsValid() || p != p.Masked() || !p.Addr().Is4() {
			return errors.New("host, pod and service CIDRs must be canonical IPv4 prefixes")
		}
		for _, q := range spaces[:i] {
			if p.Overlaps(q) {
				return errors.New("host, pod and service CIDRs overlap")
			}
		}
	}
	for i, route := range s.PodRoutes {
		if !route.IsValid() || !route.Addr().Is4() || route != route.Masked() || route.Bits() < s.PodCIDR.Bits() || !s.PodCIDR.Contains(route.Addr()) {
			return errors.New("local pod routes must be canonical prefixes inside the cluster pod range")
		}
		for _, prior := range s.PodRoutes[:i] {
			if route.Overlaps(prior) {
				return errors.New("local pod routes overlap")
			}
		}
	}
	for _, source := range s.EgressSources {
		if !source.IsValid() || source != source.Masked() || (!slices.Contains(s.Self.Addresses, source) && !(s.PodCIDR.Contains(source.Addr()) && source.Bits() >= s.PodCIDR.Bits())) {
			return errors.New("egress source must be a local overlay address or a pod prefix")
		}
	}
	seenKeys := map[key.NodePublic]bool{}
	seenIDs := map[tailcfg.NodeID]bool{}
	seenIPs := map[netip.Addr]bool{}
	nodes := append([]*tailcfg.Node{s.Self}, s.Peers...)
	for _, n := range nodes {
		if n == nil || n.Key.IsZero() || n.ID == 0 || seenKeys[n.Key] || seenIDs[n.ID] {
			return errors.New("missing or duplicate peer identity")
		}
		seenKeys[n.Key], seenIDs[n.ID] = true, true
		if n.KeyExpiry.After(time.Time{}) && !now.Before(n.KeyExpiry) {
			return fmt.Errorf("node %d key has expired", n.ID)
		}
		if len(n.Addresses) == 0 {
			return errors.New("node has no overlay address")
		}
		for _, p := range n.Addresses {
			if !p.IsValid() || !p.IsSingleIP() || !s.HostCIDR.Contains(p.Addr()) || seenIPs[p.Addr()] {
				return errors.New("invalid, duplicate or non-host overlay address")
			}
			seenIPs[p.Addr()] = true
		}
		for _, p := range n.AllowedIPs {
			if !p.IsValid() || p != p.Masked() {
				return errors.New("invalid approved route")
			}
			if p.Bits() != 0 && p.Overlaps(s.HostCIDR) && !slices.Contains(n.Addresses, p) {
				return errors.New("peer route impersonates another overlay host")
			}
			if n.Key != s.Self.Key && p.Bits() == 0 && len(s.EgressSources) == 0 {
				return errors.New("default route requires explicitly opted-in egress sources")
			}
			if !slices.Contains(n.Addresses, p) && !s.routeApproved(p) {
				return fmt.Errorf("route %s is outside the locally approved ranges", p)
			}
		}
		for _, ep := range n.Endpoints {
			if !validEndpoint(ep) {
				return errors.New("invalid peer endpoint")
			}
		}
	}
	for k, endpoints := range s.DirectHubEndpoints {
		if !seenKeys[k] {
			return errors.New("cached direct endpoint belongs to an unknown peer")
		}
		for _, ep := range endpoints {
			if !validEndpoint(ep) {
				return errors.New("invalid direct hub endpoint")
			}
		}
	}
	if _, err := filter.MatchesFromFilterRules(s.PacketFilter); err != nil {
		return fmt.Errorf("invalid packet policy: %w", err)
	}
	return nil
}

func validEndpoint(ep netip.AddrPort) bool {
	return ep.IsValid() && ep.Port() != 0 && (ep.Addr().IsGlobalUnicast() || ep.Addr().IsLoopback())
}
func (s *State) routeApproved(p netip.Prefix) bool {
	for _, a := range append([]netip.Prefix{s.PodCIDR, s.ServiceCIDR}, s.ApprovedRoutes...) {
		if a.IsValid() && a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func LoadState(dir string) (*State, error) {
	b, err := platform.ReadFile(filepath.Join(dir, "overlay.json"))
	if err != nil {
		return nil, err
	}
	var s State
	if err = json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	now := time.Now()
	s.pruneExpiredPeers(now)
	if err = s.Validate(nil, now); err != nil {
		return nil, err
	}
	s.pruneRecursiveEndpoints()
	return &s, nil
}

// A stale workstation must not prevent essential hub connectivity from being
// restored. Expired peer keys lose both routing authority and endpoint cache;
// expiration of the local identity or the trusted snapshot remains fatal.
func (s *State) pruneExpiredPeers(now time.Time) {
	s.Peers = slices.DeleteFunc(s.Peers, func(peer *tailcfg.Node) bool {
		if peer == nil || (s.Self != nil && peer.Key == s.Self.Key) || peer.KeyExpiry.IsZero() || now.Before(peer.KeyExpiry) {
			return false
		}
		delete(s.DirectHubEndpoints, peer.Key)
		return true
	})
}

func SaveState(dir string, s *State) error {
	if err := s.Validate(nil, time.Now()); err != nil {
		return err
	}
	s = s.Clone()
	s.pruneRecursiveEndpoints()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFile(filepath.Join(dir, "overlay.json"), b, false)
}

// WithEgressConfig applies a local opt-in without renewing cached trust. In
// particular, disabling egress must prune saved defaults before validation or
// an offline restart would either fail or reinstall withdrawn routing authority.
func (s *State) WithEgressConfig(sources []netip.Prefix, gateway bool) *State {
	n := s.Clone()
	n.EgressSources = slices.Clone(sources)
	n.ApprovedRoutes = slices.DeleteFunc(n.ApprovedRoutes, func(p netip.Prefix) bool { return p.Bits() == 0 })
	if gateway || len(sources) > 0 {
		n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix("0.0.0.0/0"))
	}
	for _, node := range append([]*tailcfg.Node{n.Self}, n.Peers...) {
		allowDefault := len(sources) > 0
		if node == n.Self {
			allowDefault = gateway
		}
		node.AllowedIPs = slices.DeleteFunc(node.AllowedIPs, func(p netip.Prefix) bool {
			return !slices.Contains(node.Addresses, p) && ((!allowDefault && p.Bits() == 0) || !n.routeApproved(p))
		})
		node.PrimaryRoutes = slices.DeleteFunc(node.PrimaryRoutes, func(p netip.Prefix) bool { return !slices.Contains(node.AllowedIPs, p) })
	}
	if !gateway && n.Self.Hostinfo.Valid() {
		hi := n.Self.Hostinfo.AsStruct()
		hi.RoutableIPs = slices.DeleteFunc(hi.RoutableIPs, func(p netip.Prefix) bool { return p.Bits() == 0 })
		n.Self.Hostinfo = hi.View()
	}
	return n
}

// WithMap applies a full authoritative map. Removed peers and their direct
// endpoint cache are removed together, so revocation survives a restart.
func (s *State) WithMap(m *tailcfg.MapResponse, now time.Time) (*State, error) {
	if m == nil || m.Node == nil {
		return nil, errors.New("host agent requires a complete coordinator map")
	}
	n := s.Clone()
	n.Self = m.Node.Clone()
	n.Peers = make([]*tailcfg.Node, len(m.Peers))
	n.DirectHubEndpoints = make(map[key.NodePublic][]netip.AddrPort)
	if endpoints := s.DirectHubEndpoints[s.Self.Key]; len(endpoints) > 0 {
		n.DirectHubEndpoints[s.Self.Key] = slices.Clone(endpoints)
	}
	for i, p := range m.Peers {
		if p == nil {
			return nil, errors.New("coordinator map contains a nil peer")
		}
		n.Peers[i] = p.Clone()
		n.Peers[i].AllowedIPs = slices.DeleteFunc(n.Peers[i].AllowedIPs, func(route netip.Prefix) bool {
			if slices.Contains(p.Addresses, route) {
				return false
			}
			return !n.routeApproved(route) || (route.Bits() == 0 && len(n.EgressSources) == 0)
		})
		if eps := s.DirectHubEndpoints[p.Key]; len(eps) != 0 {
			n.DirectHubEndpoints[p.Key] = slices.Clone(eps)
		}
		if slices.Contains(p.Tags, "tag:hub") && len(p.Endpoints) > 0 {
			n.DirectHubEndpoints[p.Key] = slices.Clone(p.Endpoints)
		}
	}
	n.DERPMap = m.DERPMap
	n.PacketFilter = m.PacketFilter
	n.UpdatedAt, n.ExpiresAt = now, now.Add(CacheLifetime)
	n.pruneExpiredPeers(now)
	if err := n.Validate(nil, now); err != nil {
		return nil, err
	}
	n.pruneRecursiveEndpoints()
	return n, nil
}
