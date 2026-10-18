package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// Engine is deliberately small so bootstrap ordering and recovery can be tested
// without root. The production implementation is Tailscale's actual transport.
type Engine interface {
	Apply(*State, bool) error
	Endpoints() []netip.AddrPort
	NetInfo() *tailcfg.NetInfo
	SetControlHealthy(bool)
	Rebind()
	Ping(context.Context, netip.Addr) error
	Done() <-chan struct{}
	Close()
}

type transport struct {
	e          wgengine.Engine
	magic      *magicsock.Conn
	tun        *tstun.Wrapper
	bus        *eventbus.Bus
	id         *Identity
	state      atomic.Pointer[transportState]
	mu         sync.Mutex
	endpoints  []netip.AddrPort
	netInfo    *tailcfg.NetInfo
	health     *health.Tracker
	logf       logger.Logf
	hostRouter *hostRouter
}

func NewEngine(s *State, id *Identity, logf logger.Logf) (Engine, error) {
	if err := s.Validate(id, time.Now()); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = logger.Discard
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("the host overlay agent requires Linux; use a Linux VM for a macOS worker")
	}
	if err := configureEndpointDiscovery(s); err != nil {
		return nil, err
	}
	dev, name, err := tstun.New(logf, s.Interface)
	if err != nil {
		return nil, fmt.Errorf("create overlay TUN: %w", err)
	}
	r := &hostRouter{iface: name, port: s.ListenPort, run: commandOutput, hostCIDR: s.HostCIDR, egressSources: slices.Clone(s.EgressSources), protected: []netip.Prefix{s.HostCIDR, s.PodCIDR, s.ServiceCIDR}, cniRanges: []netip.Prefix{s.PodCIDR, s.ServiceCIDR}}
	tr, err := newTransport(s, id, logf, wgengine.Config{Tun: dev, Router: r})
	if err != nil {
		dev.Close()
		_ = r.Close()
	}
	return tr, err
}

func newTransport(s *State, id *Identity, logf logger.Logf, conf wgengine.Config) (*transport, error) {
	if err := s.Validate(id, time.Now()); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = logger.Discard
	}
	t := &transport{id: id, logf: logf}
	t.hostRouter, _ = conf.Router.(*hostRouter)
	conf.ListenPort, conf.ForceDiscoKey = s.ListenPort, id.Disco
	conf.Metrics = new(usermetric.Registry)
	if conf.EventBus == nil {
		conf.EventBus = eventbus.New()
	}
	t.bus = conf.EventBus
	t.health = health.NewTracker(conf.EventBus)
	conf.HealthTracker = t.health
	conf.DERPAppName = "deepai-connect"
	conf.SetSubsystem = func(v any) {
		if c, ok := v.(*magicsock.Conn); ok {
			t.magic = c
		}
		if tun, ok := v.(*tstun.Wrapper); ok {
			t.tun = tun
		}
	}
	var err error
	t.e, err = wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		return nil, err
	}
	if t.magic == nil {
		t.e.Close()
		return nil, errors.New("Tailscale engine did not expose magicsock")
	}
	t.magic.SetNetInfoCallback(func(info *tailcfg.NetInfo) {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.netInfo = info.Clone()
	})
	t.e.SetStatusCallback(func(s *wgengine.Status, err error) {
		if err != nil || s == nil {
			return
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		t.endpoints = t.endpoints[:0]
		for _, ep := range s.LocalAddrs {
			t.endpoints = append(t.endpoints, ep.Addr)
		}
	})
	t.e.SetPeerConfigFunc(t.peerConfig)
	t.e.SetPeerByIPPacketFunc(func(ip netip.Addr) (key.NodePublic, bool) {
		p, ok := t.peerForIP(ip)
		if !ok || p.IsSelf {
			return key.NodePublic{}, false
		}
		return p.Node.Key(), true
	})
	t.e.SetPeerForIPFunc(t.peerForIP)
	if err := t.Apply(s, true); err != nil {
		t.e.Close()
		return nil, err
	}
	if t.tun != nil {
		t.tun.Start()
	}
	return t, nil
}

func nodeRoutes(n *tailcfg.Node) []netip.Prefix {
	r := slices.Clone(n.AllowedIPs)
	for _, a := range n.Addresses {
		if !slices.Contains(r, a) {
			r = append(r, a)
		}
	}
	return r
}

func (t *transport) Apply(input *State, cached bool) error {
	if err := input.Validate(t.id, time.Now()); err != nil {
		return err
	}
	s := input.Clone()
	s.pruneRecursiveEndpoints()
	old := t.state.Load()
	if old != nil && (old.Interface != s.Interface || old.ListenPort != s.ListenPort || old.ClusterID != s.ClusterID || old.endpointRanges() != s.endpointRanges() || !slices.Equal(old.Self.Addresses, s.Self.Addresses) || !slices.Equal(old.EgressSources, s.EgressSources)) {
		return errors.New("cannot change overlay identity, interface, port or host address on a running agent")
	}
	if t.hostRouter != nil {
		if err := t.hostRouter.setPodSourcePreservation(s.PodRoutes); err != nil {
			return err
		}
	}
	for _, p := range s.Peers {
		for _, ep := range s.DirectHubEndpoints[p.Key] {
			if !slices.Contains(p.Endpoints, ep) {
				p.Endpoints = append(p.Endpoints, ep)
			}
		}
	}
	matches, err := filter.MatchesFromFilterRules(s.PacketFilter)
	if err != nil {
		return err
	}
	var local netipx.IPSetBuilder
	for _, p := range nodeRoutes(s.Self) {
		local.AddPrefix(p)
	}
	localSet, err := local.IPSet()
	if err != nil {
		return err
	}
	f := filter.New(matches, nil, localSet, localSet, t.e.GetFilter(), t.logf)
	t.e.SetFilter(f)
	t.magic.SetFilter(f)
	next := newTransportState(s)
	t.state.Store(next)
	t.e.SetSelfNode(s.Self.View())
	peers := make([]tailcfg.NodeView, len(s.Peers))
	var routes []netip.Prefix
	for i, p := range s.Peers {
		peers[i] = p.View()
		routes = append(routes, next.peers[p.Key].routes...)
	}
	t.magic.SetStaticEndpoints(views.SliceOf(s.DirectHubEndpoints[s.Self.Key]))
	t.magic.SetDERPMap(s.DERPMap)
	if cached {
		t.magic.SetNetworkMapCached(s.Self.View(), peers)
	} else {
		t.magic.SetNetworkMap(s.Self.View(), peers)
	}
	if old != nil {
		for _, p := range old.Peers {
			if _, exists := next.peers[p.Key]; !exists {
				t.e.SyncDevicePeer(p.Key)
			}
		}
	}
	for _, p := range s.Peers {
		if old != nil {
			if previous, exists := old.peers[p.Key]; exists && previous.node.DiscoKey != p.DiscoKey {
				t.e.ResetDevicePeer(p.Key)
			}
		}
		t.e.SyncDevicePeer(p.Key)
	}
	err = t.e.Reconfig(&wgcfg.Config{PrivateKey: t.id.Node, Addresses: s.Self.Addresses}, &router.Config{LocalAddrs: s.Self.Addresses, Routes: routes, SubnetRoutes: s.Self.AllowedIPs}, &dns.Config{})
	if errors.Is(err, wgengine.ErrNoChanges) {
		err = nil
	}
	t.e.RequestStatus()
	return err
}

func (t *transport) Endpoints() []netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	eps := slices.Clone(t.endpoints)
	if s := t.state.Load(); s != nil {
		for _, ep := range s.DirectHubEndpoints[s.Self.Key] {
			if !slices.Contains(eps, ep) {
				eps = append(eps, ep)
			}
		}
		eps = s.UnderlayEndpoints(eps)
	}
	return eps
}

func (t *transport) NetInfo() *tailcfg.NetInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.netInfo.Clone()
}

// SetControlHealthy adapts our authenticated periodic full-map requests to the
// upstream control-health gate. Magicsock may change home DERP only while peers
// can learn that change through control. Cached restoration alone is not proof
// of control availability; the agent clears this on failed polls and shutdown.
func (t *transport) SetControlHealthy(healthy bool) {
	if healthy {
		t.health.GotStreamedMapResponse()
	} else {
		t.health.SetOutOfPollNetMap()
	}
}

// Rebind asks upstream to recheck a path that changed outside this host (for
// example, a VM's parent NAT). Its three-second DERP ping preserves healthy
// connections and reconnects stale ones, even when our local IP is unchanged.
func (t *transport) Rebind() {
	t.logf("rechecking overlay path after coordinator transport recovery")
	t.magic.Rebind()
	t.magic.ReSTUN("coordinator-transport-recovery")
}

func (t *transport) Ping(ctx context.Context, ip netip.Addr) error {
	result := make(chan *ipnstate.PingResult, 1)
	t.e.Ping(ip, tailcfg.PingTSMP, 0, func(r *ipnstate.PingResult) {
		select {
		case result <- r:
		default:
		}
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-result:
		if r.Err != "" {
			return errors.New(r.Err)
		}
		return nil
	}
}
func (t *transport) Done() <-chan struct{} { return t.e.Done() }
func (t *transport) Close() {
	t.SetControlHealthy(false)
	t.e.Close()
	t.bus.Close()
}
