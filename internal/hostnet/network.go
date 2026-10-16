package hostnet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// NetworkReport contains only displayable inventory and timestamped observations.
// UpdatedAt is the snapshot timestamp, not proof of coordinator connectivity.
type NetworkReport struct {
	SchemaVersion int             `json:"schemaVersion"`
	Source        NetworkSource   `json:"source"`
	UpdatedAt     time.Time       `json:"updatedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	MeshCIDR      netip.Prefix    `json:"meshCIDR"`
	PodCIDR       netip.Prefix    `json:"podCIDR"`
	ServiceCIDR   netip.Prefix    `json:"serviceCIDR"`
	Devices       []NetworkDevice `json:"devices"`
	Complete      bool            `json:"complete"`
	Error         string          `json:"error,omitempty"`
}

type NetworkSource struct {
	Name string     `json:"name"`
	IP   netip.Addr `json:"ip"`
}

type NetworkDevice struct {
	Name         string     `json:"name"`
	IP           netip.Addr `json:"ip"`
	Source       bool       `json:"source,omitempty"`
	Cached       bool       `json:"cached,omitempty"`
	Path         string     `json:"path"`
	Relay        string     `json:"relay,omitempty"`
	PathResult   string     `json:"pathResult"`
	PathAt       *time.Time `json:"pathAt,omitempty"`
	RTTMs        *float64   `json:"rttMs"`
	TunnelResult string     `json:"tunnelResult"`
	TunnelAt     *time.Time `json:"tunnelAt,omitempty"`
}

var ErrNetworkUnsupported = errors.New("network diagnostics require an updated host agent")

// Network reads the running host agent. It deliberately never falls back to
// disk: an old snapshot alone says nothing about a running network.
func Network(ctx context.Context, dir string) (*NetworkReport, error) {
	var report NetworkReport
	if err := request(ctx, dir, "GET", "/network/v1", nil, &report); err != nil {
		var response *agentHTTPError
		if errors.As(err, &response) && response.status == 404 {
			return nil, ErrNetworkUnsupported
		}
		return nil, err
	}
	if report.SchemaVersion != 1 {
		return nil, fmt.Errorf("unexpected network report schema version %d", report.SchemaVersion)
	}
	return &report, nil
}

// Upstream Ping has no cancellation handle and may block before installing its
// callback. Keep it optional so existing non-network engine fakes stay small.
type networkPinger interface {
	networkPing(netip.Addr, tailcfg.PingType, int, func(*ipnstate.PingResult))
}

func (t *transport) networkPing(ip netip.Addr, kind tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	t.e.Ping(ip, kind, size, cb)
}

type networkLimits struct {
	collection, peer, cooldown time.Duration
	workers                    int
}

var networkLimitsDefault = networkLimits{12 * time.Second, 3 * time.Second, 10 * time.Second, 4}

// Keep one collection in memory so repeat commands remain useful during the
// upstream probe cooldown. Identity keys stay internal and never enter reports.
type networkIdentity struct {
	id  tailcfg.NodeID
	key key.NodePublic
	ip  netip.Addr
}

type networkCache struct {
	source  networkIdentity
	until   time.Time
	devices map[networkIdentity]NetworkDevice
}

func networkNodeIdentity(n *tailcfg.Node) networkIdentity {
	return networkIdentity{n.ID, n.Key, n.Addresses[0].Addr()}
}

func networkDevice(n *tailcfg.Node) NetworkDevice {
	name := strings.TrimSuffix(n.Name, ".")
	if n.Hostinfo.Valid() && n.Hostinfo.Hostname() != "" {
		name = n.Hostinfo.Hostname()
	}
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, name))
	ip := n.Addresses[0].Addr()
	if name == "" {
		name = ip.String()
	}
	return NetworkDevice{Name: name, IP: ip, Path: "unknown", PathResult: "not tested", TunnelResult: "not tested"}
}

func (a *agent) network(ctx context.Context, limits networkLimits) *NetworkReport {
	// Copy only the public fields needed for display, then leave the state lock
	// alone throughout all potentially slow network work.
	now := time.Now()
	a.mu.Lock()
	s := a.state
	sourceIdentity := networkNodeIdentity(s.Self)
	identities := make(map[netip.Addr]networkIdentity, len(s.Peers))
	report := &NetworkReport{SchemaVersion: 1, UpdatedAt: s.UpdatedAt, ExpiresAt: s.ExpiresAt, MeshCIDR: s.HostCIDR, PodCIDR: s.PodCIDR, ServiceCIDR: s.ServiceCIDR}
	self := networkDevice(s.Self)
	self.Source = true
	report.Source = NetworkSource{Name: self.Name, IP: self.IP}
	report.Devices = append(report.Devices, self)
	for _, peer := range s.Peers {
		if peer.KeyExpiry.IsZero() || now.Before(peer.KeyExpiry) {
			report.Devices = append(report.Devices, networkDevice(peer))
			identities[peer.Addresses[0].Addr()] = networkNodeIdentity(peer)
		}
	}
	validUntil := s.ExpiresAt
	if !s.Self.KeyExpiry.IsZero() && s.Self.KeyExpiry.Before(validUntil) {
		validUntil = s.Self.KeyExpiry
	}
	expired := !now.Before(validUntil)
	a.mu.Unlock()
	slices.SortFunc(report.Devices[1:], func(a, b NetworkDevice) int { return a.IP.Compare(b.IP) })
	if expired {
		report.Error = "trusted snapshot or device identity has expired; refresh with a trusted coordinator"
		return report
	}
	pinger, ok := a.engine.(networkPinger)
	if !ok {
		report.Error = ErrNetworkUnsupported.Error()
		return report
	}
	if ctx.Err() != nil {
		report.Error = "network checks interrupted"
		return report
	}
	if len(report.Devices) == 1 {
		report.Complete = true
		return report
	}
	a.networkMu.Lock()
	if a.networkBusy || time.Now().Before(a.networkReadyAt) {
		cache := a.networkCache
		if cache != nil && cache.source == sourceIdentity && now.Before(cache.until) {
			report.Complete = true
			for i := 1; i < len(report.Devices); i++ {
				current := report.Devices[i]
				if previous, ok := cache.devices[identities[current.IP]]; ok {
					previous.Name = current.Name
					previous.Cached = true
					report.Devices[i] = previous
				} else {
					report.Complete = false
				}
			}
		}
		a.networkMu.Unlock()
		if !report.Complete {
			report.Error = "network checks are busy; try again shortly"
		}
		return report
	}
	a.networkBusy = true
	a.networkMu.Unlock()

	var calls sync.WaitGroup
	defer func() {
		// No new calls can be added once all workers have exited. A stuck
		// upstream call holds admission indefinitely rather than leaking a new
		// generation on each request. Late callbacks never block.
		go func() {
			calls.Wait()
			a.networkMu.Lock()
			a.networkReadyAt = time.Now().Add(limits.cooldown)
			a.networkBusy = false
			a.networkMu.Unlock()
		}()
	}()
	ctx, cancel := context.WithDeadline(ctx, minTime(time.Now().Add(limits.collection), validUntil))
	defer cancel()
	jobs := make(chan int)
	slots := make(chan struct{}, limits.workers)
	finished := make([]bool, len(report.Devices))
	var workers sync.WaitGroup
	for range min(limits.workers, len(report.Devices)-1) {
		workers.Go(func() {
			for i := range jobs {
				if ctx.Err() == nil {
					finished[i] = probeNetworkPeer(ctx, pinger, &report.Devices[i], limits.peer, &calls, slots)
				}
			}
		})
	}
schedule:
	for i := 1; i < len(report.Devices); i++ {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break schedule
		}
	}
	close(jobs)
	workers.Wait()
	report.Complete = !slices.Contains(finished[1:], false)
	if !report.Complete {
		report.Error = "network checks interrupted; some devices were not fully tested"
	}
	a.networkMu.Lock()
	// Always replace the previous collection, including failed observations.
	// An interrupted collection must not fall back to an older healthy result.
	a.networkCache = nil
	if report.Complete {
		cache := &networkCache{source: sourceIdentity, until: minTime(now.Add(30*time.Second), validUntil), devices: make(map[networkIdentity]NetworkDevice, len(identities))}
		for _, device := range report.Devices[1:] {
			cache.devices[identities[device.IP]] = device
		}
		a.networkCache = cache
	}
	a.networkMu.Unlock()
	return report
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type networkReply struct {
	result ipnstate.PingResult
	at     time.Time
}

type networkAttempt struct {
	replies chan networkReply
	started atomic.Bool
}

func networkProbe(ctx context.Context, pinger networkPinger, ip netip.Addr, kind tailcfg.PingType, calls *sync.WaitGroup, returned func()) *networkAttempt {
	attempt := &networkAttempt{replies: make(chan networkReply, 1)}
	calls.Go(func() {
		defer returned()
		if ctx.Err() != nil {
			return
		}
		attempt.started.Store(true)
		// A nonzero discovery size avoids the optional upstream MTU sweep.
		pinger.networkPing(ip, kind, 128, func(result *ipnstate.PingResult) {
			reply := networkReply{at: time.Now(), result: ipnstate.PingResult{Err: "empty reply"}}
			if result != nil {
				reply.result = *result
			}
			select {
			case attempt.replies <- reply:
			default:
			}
		})
	})
	return attempt
}

// The discovery reply describes a path; TSMP separately measures the encrypted
// tunnel. Neither observation claims that an application or the reverse path works.
func probeNetworkPeer(parent context.Context, pinger networkPinger, device *NetworkDevice, timeout time.Duration, calls *sync.WaitGroup, slots chan struct{}) bool {
	// A callback can precede a blocked Ping return. Keep the pair's slot until
	// both synchronous calls return, even after this peer's observation ends.
	select {
	case slots <- struct{}{}:
	case <-parent.Done():
		return false
	}
	var pending atomic.Int32
	pending.Store(2)
	returned := func() {
		if pending.Add(-1) == 0 {
			<-slots
		}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	tunnelAttempt := networkProbe(ctx, pinger, device.IP, tailcfg.PingTSMP, calls, returned)
	pathAttempt := networkProbe(ctx, pinger, device.IP, tailcfg.PingDisco, calls, returned)
	tunnel, path := tunnelAttempt.replies, pathAttempt.replies
	for tunnel != nil || path != nil {
		select {
		case reply := <-tunnel:
			if reply.at.After(deadline) {
				continue
			}
			tunnel = nil
			device.TunnelAt = &reply.at
			device.TunnelResult = "error"
			ms := reply.result.LatencySeconds * 1000
			if reply.result.Err == "" && ms >= 0 && !math.IsNaN(ms) && !math.IsInf(ms, 0) {
				device.RTTMs = &ms
				device.TunnelResult = "reply"
			}
		case reply := <-path:
			if reply.at.After(deadline) {
				continue
			}
			path = nil
			device.PathAt = &reply.at
			device.PathResult = "error"
			if reply.result.Err == "" {
				device.PathResult = "reply"
				switch {
				case reply.result.PeerRelay != "":
					device.Path, device.Relay = "relay", "peer"
				case reply.result.DERPRegionID != 0:
					device.Path, device.Relay = "relay", "derp"
				case reply.result.Endpoint != "":
					device.Path = "direct"
				}
			}
		case <-ctx.Done():
			if parent.Err() != nil {
				return false
			}
			now := time.Now()
			if tunnel != nil && tunnelAttempt.started.Load() {
				device.TunnelAt, device.TunnelResult = &now, "no reply"
			}
			if path != nil && pathAttempt.started.Load() {
				device.PathAt, device.PathResult = &now, "no reply"
			}
			return tunnelAttempt.started.Load() && pathAttempt.started.Load()
		}
	}
	return true
}
