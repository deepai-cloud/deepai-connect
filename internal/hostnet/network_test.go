package hostnet

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type networkTestEngine struct {
	testEngine
	probe func(netip.Addr, tailcfg.PingType, int, func(*ipnstate.PingResult))
}

func (e *networkTestEngine) networkPing(ip netip.Addr, kind tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	e.probe(ip, kind, size, cb)
}

func networkTestAgent(t *testing.T, count int, probe func(netip.Addr, tailcfg.PingType, int, func(*ipnstate.PingResult))) *agent {
	t.Helper()
	s, id := testState(t, 1)
	s.Self.Hostinfo = (&tailcfg.Hostinfo{Hostname: "hub"}).View()
	for i := count + 1; i > 1; i-- {
		p, _ := testState(t, uint8(i))
		s.Peers = append(s.Peers, p.Self)
	}
	return &agent{state: s, identity: id, engine: &networkTestEngine{probe: probe}}
}

var testNetworkLimits = networkLimits{200 * time.Millisecond, 20 * time.Millisecond, 10 * time.Millisecond, 4}

func TestNetworkRepeatKeepsRecentLatency(t *testing.T) {
	var calls atomic.Int32
	a := networkTestAgent(t, 1, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		calls.Add(1)
		cb(&ipnstate.PingResult{LatencySeconds: .048, Endpoint: "203.0.113.1:41641"})
	})
	limits := testNetworkLimits
	limits.cooldown = time.Hour
	first := a.network(context.Background(), limits)
	a.state.UpdatedAt = time.Now()
	a.state.Peers[0].Hostinfo = (&tailcfg.Hostinfo{Hostname: "renamed-worker"}).View()
	for range 10 {
		r := a.network(context.Background(), limits)
		d := r.Devices[1]
		if !r.Complete || r.Error != "" || !d.Cached || d.RTTMs == nil || *d.RTTMs != 48 || d.Path != "direct" || calls.Load() != 2 {
			t.Fatalf("repeat lost latency or started another probe: %+v, calls=%d", r, calls.Load())
		}
		if d.Name != "renamed-worker" || !r.UpdatedAt.Equal(a.state.UpdatedAt) || !d.TunnelAt.Equal(*first.Devices[1].TunnelAt) || !d.PathAt.Equal(*first.Devices[1].PathAt) {
			t.Fatal("cache replaced current inventory or changed measurement times")
		}
		data, _ := json.Marshal(r)
		if !strings.Contains(string(data), `"cached":true`) || strings.Contains(string(data), a.state.Peers[0].Key.String()) {
			t.Fatal("cache marker missing or identity key leaked")
		}
	}
	if first.Devices[1].Cached {
		t.Fatal("repeat mutated the original report")
	}
}

func TestNetworkCacheDoesNotOutliveIdentityOrTrust(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*agent)
	}{
		{"peer key changed", func(a *agent) { a.state.Peers[0].Key = key.NewNode().Public() }},
		{"peer ID changed", func(a *agent) { a.state.Peers[0].ID++ }},
		{"peer IP changed", func(a *agent) { a.state.Peers[0].Addresses[0] = netip.MustParsePrefix("100.64.0.99/32") }},
		{"source key changed", func(a *agent) { a.state.Self.Key = key.NewNode().Public() }},
		{"source IP changed", func(a *agent) { a.state.Self.Addresses[0] = netip.MustParsePrefix("100.64.0.99/32") }},
		{"source expired", func(a *agent) { a.state.Self.KeyExpiry = time.Now().Add(-time.Second) }},
		{"snapshot expired", func(a *agent) { a.state.ExpiresAt = time.Now().Add(-time.Second) }},
		{"peer expired", func(a *agent) { a.state.Peers[0].KeyExpiry = time.Now().Add(-time.Second) }},
		{"peer removed", func(a *agent) { a.state.Peers = nil }},
		{"cache expired", func(a *agent) {
			a.networkMu.Lock()
			a.networkCache.until = time.Now().Add(-time.Second)
			a.networkMu.Unlock()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			a := networkTestAgent(t, 1, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
				calls.Add(1)
				cb(&ipnstate.PingResult{LatencySeconds: .01})
			})
			limits := testNetworkLimits
			limits.cooldown = time.Hour
			if !a.network(context.Background(), limits).Complete {
				t.Fatal("initial collection incomplete")
			}
			test.change(a)
			r := a.network(context.Background(), limits)
			for _, d := range r.Devices {
				if d.Cached || d.RTTMs != nil {
					t.Fatalf("reused invalid observation: %+v", d)
				}
			}
			if calls.Load() != 2 {
				t.Fatal("cache invalidation bypassed cooldown")
			}
		})
	}
}

func TestNetworkNewFailureReplacesCachedSuccess(t *testing.T) {
	var failed atomic.Bool
	started := make(chan struct{}, 2)
	unblock := make(chan struct{})
	a := networkTestAgent(t, 1, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		if failed.Load() {
			started <- struct{}{}
			<-unblock
			cb(&ipnstate.PingResult{Err: "unreachable"})
			return
		}
		cb(&ipnstate.PingResult{LatencySeconds: .01})
	})
	first := a.network(context.Background(), testNetworkLimits)
	if !first.Complete {
		t.Fatal("initial collection incomplete")
	}
	deadline := time.Now().Add(time.Second)
	for {
		a.networkMu.Lock()
		ready := !a.networkBusy
		if ready {
			a.networkReadyAt = time.Time{}
		}
		a.networkMu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial upstream calls never returned")
		}
		time.Sleep(time.Millisecond)
	}
	failed.Store(true)
	done := make(chan *NetworkReport, 1)
	go func() { done <- a.network(context.Background(), networkLimits{time.Second, time.Second, time.Hour, 4}) }()
	for range 2 {
		<-started
	}
	during := a.network(context.Background(), testNetworkLimits)
	if !during.Complete || !during.Devices[1].Cached || during.Devices[1].RTTMs == nil {
		t.Fatal("in-flight collection hid the recent measurement")
	}
	close(unblock)
	fresh := <-done
	repeated := a.network(context.Background(), testNetworkLimits)
	if !fresh.Complete || fresh.Devices[1].Cached || fresh.Devices[1].TunnelResult != "error" || !repeated.Complete || !repeated.Devices[1].Cached || repeated.Devices[1].TunnelResult != "error" || repeated.Devices[1].RTTMs != nil {
		t.Fatalf("old success masked new failure: fresh=%+v repeat=%+v", fresh.Devices[1], repeated.Devices[1])
	}
}

func TestNetworkObservationsAreIndependent(t *testing.T) {
	for _, test := range []struct {
		name          string
		tunnel, path  *ipnstate.PingResult
		wantTunnel    string
		wantPath      string
		wantRelay     string
		wantDiscovery string
	}{
		{"direct", &ipnstate.PingResult{LatencySeconds: .08}, &ipnstate.PingResult{Endpoint: "203.0.113.1:41641", LatencySeconds: .02}, "reply", "direct", "", "reply"},
		{"DERP", &ipnstate.PingResult{LatencySeconds: .08}, &ipnstate.PingResult{DERPRegionID: 1}, "reply", "relay", "derp", "reply"},
		{"peer relay", &ipnstate.PingResult{LatencySeconds: .08}, &ipnstate.PingResult{PeerRelay: "100.64.0.3:41641:vni:1"}, "reply", "relay", "peer", "reply"},
		{"tunnel only", &ipnstate.PingResult{LatencySeconds: .08}, nil, "reply", "unknown", "", "no reply"},
		{"discovery only", nil, &ipnstate.PingResult{Endpoint: "203.0.113.1:41641"}, "no reply", "direct", "", "reply"},
		{"silent", nil, nil, "no reply", "unknown", "", "no reply"},
		{"removed peer", &ipnstate.PingResult{Err: "unknown peer"}, &ipnstate.PingResult{Err: "unknown peer"}, "error", "unknown", "", "error"},
		{"invalid latency", &ipnstate.PingResult{LatencySeconds: math.NaN()}, &ipnstate.PingResult{}, "error", "unknown", "", "reply"},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := networkTestAgent(t, 1, func(_ netip.Addr, kind tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
				if size != 128 {
					t.Errorf("unexpected probe size %d", size)
				}
				if kind == tailcfg.PingTSMP && test.tunnel != nil {
					cb(test.tunnel)
				} else if kind == tailcfg.PingDisco && test.path != nil {
					cb(test.path)
				}
			})
			r := a.network(context.Background(), testNetworkLimits)
			d := r.Devices[1]
			if !r.Complete || d.TunnelResult != test.wantTunnel || d.Path != test.wantPath || d.Relay != test.wantRelay || d.PathResult != test.wantDiscovery {
				t.Fatalf("unexpected report: %+v / %+v", r, d)
			}
			if d.TunnelAt == nil || d.PathAt == nil {
				t.Fatal("missing independent observation times")
			}
			if test.wantTunnel == "reply" {
				if d.RTTMs == nil || *d.RTTMs != 80 {
					t.Fatalf("RTT is not from TSMP: %v", d.RTTMs)
				}
			} else if d.RTTMs != nil {
				t.Fatalf("invented RTT: %v", d.RTTMs)
			}
		})
	}
}

func TestNetworkInventoryIsAllowlistedAndReadOnly(t *testing.T) {
	a := networkTestAgent(t, 3, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		cb(&ipnstate.PingResult{})
	})
	a.state.ClusterID = "secret-cluster-canary"
	a.state.CoordinatorURL = "https://secret-coordinator-canary.example"
	a.state.PacketFilter = []tailcfg.FilterRule{{SrcIPs: []string{"secret-policy-canary"}}}
	before, _ := json.Marshal(a.state)
	r := a.network(context.Background(), testNetworkLimits)
	after, _ := json.Marshal(a.state)
	if string(before) != string(after) || a.engine.(*networkTestEngine).rebinds.Load() != 0 {
		t.Fatal("network collection changed live state or paths")
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _ := a.identity.Node.MarshalText()
	for _, private := range []string{"secret-", string(privateKey), a.state.Self.Key.String(), "PacketFilter", "DERPMap", "AllowedIPs"} {
		if strings.Contains(string(data), private) {
			t.Fatalf("network report leaked %s", private)
		}
	}
	if r.Source.Name != "hub" || r.Source.IP != r.Devices[0].IP || !r.Devices[0].Source || r.Devices[0].RTTMs != nil || !r.UpdatedAt.Equal(a.state.UpdatedAt) {
		t.Fatal("incorrect source or snapshot metadata")
	}
	for i, d := range r.Devices {
		if d.IP.As4()[3] != uint8(i+1) {
			t.Fatal("devices are not in stable numeric IP order")
		}
	}
}

func TestNetworkMalformedReplyNeverInventsRTT(t *testing.T) {
	for _, response := range []*ipnstate.PingResult{nil, {LatencySeconds: math.MaxFloat64}, {LatencySeconds: -1}} {
		a := networkTestAgent(t, 1, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) { cb(response) })
		r := a.network(context.Background(), testNetworkLimits)
		if !r.Complete || r.Devices[1].TunnelResult != "error" || r.Devices[1].RTTMs != nil {
			t.Fatalf("malformed reply produced RTT: %+v", r.Devices[1])
		}
		if _, err := json.Marshal(r); err != nil {
			t.Fatalf("report cannot be encoded: %v", err)
		}
	}
}

func TestNetworkNamesCannotControlTerminal(t *testing.T) {
	a := networkTestAgent(t, 1, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		cb(&ipnstate.PingResult{})
	})
	hostile := "home\tworker\n\x1b[31m\x1b]8;;https://example.com\a\u202e"
	a.state.Self.Hostinfo = (&tailcfg.Hostinfo{Hostname: hostile}).View()
	a.state.Peers[0].Hostinfo = (&tailcfg.Hostinfo{Hostname: hostile}).View()
	r := a.network(context.Background(), testNetworkLimits)
	for _, name := range []string{r.Source.Name, r.Devices[0].Name, r.Devices[1].Name} {
		if name == "" || strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			t.Fatalf("unsafe display name: %q", name)
		}
	}
	if a.state.Self.Hostinfo.Hostname() != hostile {
		t.Fatal("sanitization changed authoritative state")
	}
}

func TestNetworkExpiredStateNeverProbes(t *testing.T) {
	for _, identityExpired := range []bool{false, true} {
		a := networkTestAgent(t, 1, func(netip.Addr, tailcfg.PingType, int, func(*ipnstate.PingResult)) {
			t.Error("expired authority started a probe")
		})
		if identityExpired {
			a.state.Self.KeyExpiry = time.Now().Add(-time.Second)
		} else {
			a.state.ExpiresAt = time.Now().Add(-time.Second)
		}
		r := a.network(context.Background(), testNetworkLimits)
		if r.Complete || !strings.Contains(r.Error, "expired") || r.Devices[1].TunnelResult != "not tested" {
			t.Fatalf("expired snapshot appeared healthy: %+v", r)
		}
	}
}

func TestNetworkCancellationAndStuckCallsDoNotAdmitMoreProbes(t *testing.T) {
	var count atomic.Int32
	blocked := make(chan struct{})
	started := make(chan struct{}, 8)
	var callbacksMu sync.Mutex
	var callbacks []func(*ipnstate.PingResult)
	a := networkTestAgent(t, 20, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		count.Add(1)
		callbacksMu.Lock()
		callbacks = append(callbacks, cb)
		callbacksMu.Unlock()
		started <- struct{}{}
		<-blocked
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *NetworkReport, 1)
	go func() { done <- a.network(ctx, networkLimits{time.Second, time.Second, 10 * time.Millisecond, 4}) }()
	for range 8 {
		<-started
	}
	// Inventory refresh must stay responsive while the transport is blocked.
	a.mu.Lock()
	a.state.UpdatedAt = time.Now()
	a.mu.Unlock()
	cancel()
	var report *NetworkReport
	select {
	case report = <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for synchronous upstream calls")
	}
	if report.Complete || report.Error == "" || count.Load() != 8 {
		t.Fatalf("unbounded or complete canceled collection: %+v, calls %d", report, count.Load())
	}
	before, _ := json.Marshal(report)
	for range 10 {
		r := a.network(context.Background(), testNetworkLimits)
		if r.Complete || !strings.Contains(r.Error, "busy") || count.Load() != 8 {
			t.Fatal("a stuck generation admitted more work")
		}
	}
	callbacksMu.Lock()
	for _, cb := range callbacks {
		for range 10 {
			cb(&ipnstate.PingResult{LatencySeconds: .001, Endpoint: "203.0.113.1:41641"})
		}
	}
	callbacksMu.Unlock()
	after, _ := json.Marshal(report)
	if string(before) != string(after) {
		t.Fatal("late callbacks modified a returned report")
	}
	released := time.Now()
	close(blocked)
	deadline := time.Now().Add(time.Second)
	for {
		a.networkMu.Lock()
		busy, readyAt := a.networkBusy, a.networkReadyAt
		a.networkMu.Unlock()
		if !busy {
			if readyAt.Before(released.Add(10 * time.Millisecond)) {
				t.Fatal("no cooldown after synchronous calls returned")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admission never released")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNetworkEarlyCallbacksDoNotBypassCallLimit(t *testing.T) {
	var calls atomic.Int32
	blocked := make(chan struct{})
	defer close(blocked)
	a := networkTestAgent(t, 20, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		calls.Add(1)
		cb(&ipnstate.PingResult{LatencySeconds: .01, Endpoint: "203.0.113.1:41641"})
		<-blocked
	})
	start := time.Now()
	r := a.network(context.Background(), networkLimits{40 * time.Millisecond, 20 * time.Millisecond, time.Millisecond, 4})
	if r.Complete || calls.Load() != 8 || time.Since(start) > time.Second {
		t.Fatalf("early callbacks bypassed bounds: complete=%v calls=%d", r.Complete, calls.Load())
	}
	next := a.network(context.Background(), testNetworkLimits)
	if next.Complete || !strings.Contains(next.Error, "busy") || calls.Load() != 8 {
		t.Fatal("blocked call returns admitted another generation")
	}
}

func TestNetworkCollectorDeadlineReturnsPartialInventory(t *testing.T) {
	var calls atomic.Int32
	a := networkTestAgent(t, 20, func(netip.Addr, tailcfg.PingType, int, func(*ipnstate.PingResult)) { calls.Add(1) })
	started := time.Now()
	r := a.network(context.Background(), networkLimits{35 * time.Millisecond, 30 * time.Millisecond, time.Millisecond, 4})
	if r.Complete || len(r.Devices) != 21 || calls.Load() > 16 || time.Since(started) > time.Second {
		t.Fatalf("collector exceeded its budget or lost inventory: %+v, calls %d", r, calls.Load())
	}
	if r.Devices[20].TunnelResult != "not tested" || r.Devices[20].RTTMs != nil {
		t.Fatal("unstarted device was reported as failed")
	}
}

func serveNetworkTest(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "netapi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	listener, err := net.Listen("unix", SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return dir
}

func TestNetworkEndpointCompatibilityAndNoDiskFallback(t *testing.T) {
	a := networkTestAgent(t, 1, func(_ netip.Addr, _ tailcfg.PingType, _ int, cb func(*ipnstate.PingResult)) {
		cb(&ipnstate.PingResult{})
	})
	dir := serveNetworkTest(t, a.handler())
	if r, err := Network(context.Background(), dir); err != nil || r.SchemaVersion != 1 || !r.Complete {
		t.Fatalf("network endpoint: %+v, %v", r, err)
	}
	old := serveNetworkTest(t, http.NewServeMux())
	if _, err := Network(context.Background(), old); !errors.Is(err, ErrNetworkUnsupported) {
		t.Fatalf("missing endpoint was not identified: %v", err)
	}
	broken := serveNetworkTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	if _, err := Network(context.Background(), broken); err == nil || errors.Is(err, ErrNetworkUnsupported) {
		t.Fatalf("operational error was misclassified: %v", err)
	}
	invalid := serveNetworkTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("invalid JSON")) }))
	if _, err := Network(context.Background(), invalid); err == nil || errors.Is(err, ErrNetworkUnsupported) {
		t.Fatalf("bad report was misclassified: %v", err)
	}
	missing := t.TempDir()
	if err := SaveState(missing, a.state); err != nil {
		t.Fatal(err)
	}
	if _, err := Network(context.Background(), missing); err == nil || errors.Is(err, ErrNetworkUnsupported) {
		t.Fatalf("missing agent used a cached snapshot or appeared old: %v", err)
	}
}
