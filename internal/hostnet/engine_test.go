package hostnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
)

func udpPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.LocalAddr().(*net.UDPAddr).Port)
}

func TestEncryptedDERPFallbackWhenUDPUnavailable(t *testing.T) {
	relay := derpserver.New(key.NewNode(), logger.Discard)
	defer relay.Close()
	server := httptest.NewTLSServer(derpserver.Handler(relay))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	certHash := sha256.Sum256(server.Certificate().Raw)
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{Name: "test1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", STUNPort: -1, DERPPort: port, CertName: "sha256-raw:" + hex.EncodeToString(certHash[:])}}}}}
	a, aid := testState(t, 1)
	b, bid := testState(t, 2)
	a.ListenPort, b.ListenPort = udpPort(t), udpPort(t)
	a.DERPMap, b.DERPMap = dm, dm
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	ea, err := newTransport(a, aid, logger.Logf(t.Logf), wgengine.Config{RespondToPing: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ea.Close()
	eb, err := newTransport(b, bid, logger.Logf(t.Logf), wgengine.Config{RespondToPing: true})
	if err != nil {
		t.Fatal(err)
	}
	defer eb.Close()
	ea.magic.SetOnlyTCP443(true)
	eb.magic.SetOnlyTCP443(true)
	ea.magic.ReSTUN("test-tcp-only")
	eb.magic.ReSTUN("test-tcp-only")
	// Discover the relay through the real network monitor. Neither node begins
	// with a hardcoded HomeDERP; the coordinator learns it from live NetInfo.
	deadline := time.Now().Add(15 * time.Second)
	for {
		ai, bi := ea.NetInfo(), eb.NetInfo()
		if ai != nil && bi != nil && ai.PreferredDERP != 0 && bi.PreferredDERP != 0 {
			a.Self.HomeDERP, b.Self.HomeDERP = ai.PreferredDERP, bi.PreferredDERP
			a.Self.Hostinfo = (&tailcfg.Hostinfo{NetInfo: ai}).View()
			b.Self.Hostinfo = (&tailcfg.Hostinfo{NetInfo: bi}).View()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("DERP discovery reports did not arrive: a=%v b=%v", ai, bi)
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	if err := ea.Apply(a, false); err != nil {
		t.Fatal(err)
	}
	if err := eb.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := ea.Ping(ctx, b.Self.Addresses[0].Addr()); err != nil {
		t.Fatalf("encrypted relay ping: %v", err)
	}
	if err := eb.Ping(ctx, a.Self.Addresses[0].Addr()); err != nil {
		t.Fatalf("encrypted relay return path: %v", err)
	}
}

// Exercises the real WireGuard and magicsock code, with fake OS TUN devices.
// Both peers start from disk-equivalent cached maps with direct hub endpoints;
// no coordinator, Kubernetes, DNS or DERP server participates in the handshake.
func TestCachedPeersCommunicateWithoutControlPlane(t *testing.T) {
	a, aid := testState(t, 1)
	b, bid := testState(t, 2)
	a.ListenPort, b.ListenPort = udpPort(t), udpPort(t)
	aep := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.ListenPort)
	bep := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.ListenPort)
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	a.DirectHubEndpoints = map[key.NodePublic][]netip.AddrPort{b.Self.Key: {bep}}
	b.DirectHubEndpoints = map[key.NodePublic][]netip.AddrPort{a.Self.Key: {aep}}
	// Previously saved CNI/overlay endpoints must not enter magicsock, even
	// when restoring without a control plane to replace the old snapshot.
	a.DirectHubEndpoints[b.Self.Key] = append(a.DirectHubEndpoints[b.Self.Key], netip.MustParseAddrPort("10.42.0.1:41641"))
	b.DirectHubEndpoints[a.Self.Key] = append(b.DirectHubEndpoints[a.Self.Key], netip.MustParseAddrPort("100.64.0.1:41641"))
	// The only endpoints are those recovered from the direct endpoint cache.
	a.Peers[0].Endpoints, b.Peers[0].Endpoints = nil, nil
	start := func(s *State, id *Identity) *transport {
		t.Helper()
		e, err := newTransport(s, id, logger.Logf(t.Logf), wgengine.Config{RespondToPing: true})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	ea, eb := start(a, aid), start(b, bid)
	if !slices.Equal(ea.state.Load().Peers[0].Endpoints, []netip.AddrPort{bep}) || !slices.Equal(eb.state.Load().Peers[0].Endpoints, []netip.AddrPort{aep}) {
		t.Fatal("recursive cached endpoints reached the engine")
	}
	defer ea.Close()
	defer eb.Close()
	ping := func(e *transport, ip netip.Addr) {
		t.Helper()
		deadline := time.Now().Add(25 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err = e.Ping(ctx, ip)
			cancel()
			if err == nil {
				return
			}
		}
		t.Fatalf("cached overlay ping failed: %v", err)
	}
	ping(ea, b.Self.Addresses[0].Addr())
	ping(eb, a.Self.Addresses[0].Addr())
	// A live map updates the existing engine rather than exchanging transports.
	a.UpdatedAt = time.Now()
	a.ExpiresAt = a.UpdatedAt.Add(CacheLifetime)
	if err := ea.Apply(a, false); err != nil {
		t.Fatal(err)
	}
	ping(ea, b.Self.Addresses[0].Addr())
	// Simultaneous restart still uses the same saved device/discovery identities.
	ea.Close()
	eb.Close()
	ea, eb = start(a, aid), start(b, bid)
	defer ea.Close()
	defer eb.Close()
	ping(ea, b.Self.Addresses[0].Addr())
	ping(eb, a.Self.Addresses[0].Addr())
}
