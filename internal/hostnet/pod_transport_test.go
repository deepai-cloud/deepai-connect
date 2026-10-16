package hostnet

import (
	"context"
	"io"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
)

// packetTUN substitutes only the OS boundary; WireGuard, packet filtering,
// source authorization, discovery and encrypted UDP transport remain real.
type packetTUN struct {
	fromOS chan []byte
	toOS   chan []byte
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newPacketTUN() *packetTUN {
	return &packetTUN{fromOS: make(chan []byte, 16), toOS: make(chan []byte, 16), events: make(chan tun.Event), closed: make(chan struct{})}
}
func (t *packetTUN) File() *os.File { return nil }
func (t *packetTUN) Close() error   { t.once.Do(func() { close(t.closed); close(t.events) }); return nil }
func (t *packetTUN) Read(out [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	case p := <-t.fromOS:
		sizes[0] = copy(out[0][offset:], p)
		return 1, nil
	}
}
func (t *packetTUN) Write(packets [][]byte, offset int) (int, error) {
	for _, p := range packets {
		select {
		case <-t.closed:
			return 0, io.EOF
		case t.toOS <- slices.Clone(p[offset:]):
		}
	}
	return len(packets), nil
}
func (t *packetTUN) MTU() (int, error)        { return 1280, nil }
func (t *packetTUN) Name() (string, error)    { return "FakeTUN", nil }
func (t *packetTUN) Events() <-chan tun.Event { return t.events }
func (t *packetTUN) BatchSize() int           { return 1 }
func (t *packetTUN) IsFakeTun() bool          { return true }

func TestEncryptedPodSourceAndReturnPath(t *testing.T) {
	useLoopbackTransport(t)
	worker, wid := testState(t, 2)
	host, hid := testState(t, 1)
	worker.Self.Hostinfo = (&tailcfg.Hostinfo{Hostname: "worker"}).View()
	host.Self.Hostinfo = (&tailcfg.Hostinfo{Hostname: "private-host"}).View()
	podRange := netip.MustParsePrefix("10.42.2.0/24")
	podIP := netip.MustParseAddr("10.42.2.5")
	hostIP := host.Self.Addresses[0].Addr()
	worker.PodRoutes = []netip.Prefix{podRange}
	// Represents the coordinator's approval after verifying Kubernetes' own
	// node.spec.podCIDR, not just a client's claimed advertised subnet.
	worker.Self.AllowedIPs = append(worker.Self.AllowedIPs, podRange)
	worker.ListenPort, host.ListenPort = udpPort(t), udpPort(t)
	worker.Peers, host.Peers = []*tailcfg.Node{host.Self.Clone()}, []*tailcfg.Node{worker.Self.Clone()}
	worker.DirectHubEndpoints = map[key.NodePublic][]netip.AddrPort{host.Self.Key: {netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), host.ListenPort)}}
	host.DirectHubEndpoints = map[key.NodePublic][]netip.AddrPort{worker.Self.Key: {netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), worker.ListenPort)}}
	policy := []tailcfg.FilterRule{{SrcIPs: []string{worker.HostCIDR.String(), worker.PodCIDR.String()}, DstPorts: []tailcfg.NetPortRange{{IP: worker.HostCIDR.String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}}, {IP: worker.PodCIDR.String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}}}}}
	worker.PacketFilter, host.PacketFilter = policy, policy
	wt, ht := newPacketTUN(), newPacketTUN()
	we, err := newTransport(worker, wid, logger.Logf(t.Logf), wgengine.Config{Tun: wt})
	if err != nil {
		t.Fatal(err)
	}
	defer we.Close()
	he, err := newTransport(host, hid, logger.Logf(t.Logf), wgengine.Config{Tun: ht})
	if err != nil {
		t.Fatal(err)
	}
	defer he.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Establish discovery in both directions before testing payload routing.
	discovered := make(chan *ipnstate.PingResult, 2)
	we.e.Ping(hostIP, tailcfg.PingDisco, 0, func(r *ipnstate.PingResult) { discovered <- r })
	he.e.Ping(worker.Self.Addresses[0].Addr(), tailcfg.PingDisco, 0, func(r *ipnstate.PingResult) { discovered <- r })
	for range 2 {
		select {
		case result := <-discovered:
			if result.Err != "" {
				t.Fatal(result.Err)
			}
		case <-ctx.Done():
			t.Fatal("direct discovery timed out")
		}
	}
	udp := func(src, dst netip.Addr, payload string) []byte {
		sourcePort, destinationPort := uint16(12345), uint16(23456)
		if src == hostIP {
			sourcePort, destinationPort = destinationPort, sourcePort
		}
		return packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{Src: src, Dst: dst}, SrcPort: sourcePort, DstPort: destinationPort}, []byte(payload))
	}
	wt.fromOS <- udp(podIP, hostIP, "pod-to-private-host")
	receive := func(tun *packetTUN, wantSource, wantDestination netip.Addr, wantPayload string) {
		t.Helper()
		select {
		case data := <-tun.toOS:
			var p packet.Parsed
			p.Decode(data)
			if p.Src.Addr() != wantSource || p.Dst.Addr() != wantDestination || string(p.Payload()) != wantPayload {
				t.Fatalf("unexpected decrypted packet: %s -> %s payload=%q", p.Src, p.Dst, p.Payload())
			}
		case <-ctx.Done():
			t.Fatal("encrypted pod packet did not reach the peer OS")
		}
	}
	receive(ht, podIP, hostIP, "pod-to-private-host")
	ht.fromOS <- udp(hostIP, podIP, "reply-to-pod")
	receive(wt, hostIP, podIP, "reply-to-pod")
	// The same key must not originate a sibling node's pod subnet, even though
	// the cluster-wide packet policy allows communication with that subnet.
	wt.fromOS <- udp(netip.MustParseAddr("10.42.99.5"), hostIP, "spoofed-pod")
	select {
	case data := <-ht.toOS:
		t.Fatalf("WireGuard accepted an unauthorized pod source: %x", data)
	case <-time.After(300 * time.Millisecond):
	}
}
