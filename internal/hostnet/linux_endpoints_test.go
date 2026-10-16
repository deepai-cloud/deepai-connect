//go:build linux

package hostnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

func TestLinuxTransportBoundary(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" {
		t.Skip("requires explicitly opted-in Linux namespace test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := fmt.Sprintf("dc-endpoint-%d", os.Getpid())
	if b, err := exec.CommandContext(ctx, "ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("create namespace: %v %s", err, b)
	}
	t.Cleanup(func() {
		if b, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput(); err != nil {
			t.Errorf("remove namespace: %v %s", err, b)
		}
	})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary, "-test.run=^TestLinuxTransportBoundaryProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "DEEPAI_CONNECT_ENDPOINT_HELPER=1")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("transport boundary: %v\n%s", err, b)
	}
	t.Log(string(b))
}

func TestLinuxTransportBoundaryProcess(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_ENDPOINT_HELPER") != "1" {
		t.Skip("namespace subprocess helper")
	}
	must := func(name string, args ...string) string {
		t.Helper()
		b, err := commandOutput(name, args...)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	must("ip", "link", "set", "lo", "up")
	for iface, address := range map[string]string{"eth0": "198.18.0.1/24", "lan0": "192.168.64.3/24", "cni0": "10.42.0.1/24", "deepai0": "100.64.0.1/32", "service0": "10.43.0.10/32"} {
		must("ip", "link", "add", iface, "type", "dummy")
		must("ip", "address", "add", address, "dev", iface)
		must("ip", "link", "set", iface, "up")
	}
	s, _ := testState(t, 1)
	if err := configureEndpointDiscovery(s); err != nil {
		t.Fatal(err)
	}
	addresses, _, err := netmon.LocalAddresses()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range addresses {
		if s.endpointRanges().contains(ip) {
			t.Fatalf("upstream CallMeMaybe discovery retains recursive address %v", ip)
		}
	}
	for _, want := range []string{"198.18.0.1", "192.168.64.3"} {
		if !slices.Contains(addresses, netip.MustParseAddr(want)) {
			t.Fatalf("underlay discovery lost %s: %v", want, addresses)
		}
	}
	// A read-only nft-backed -S does not instantiate an absent raw table.
	// Preserve a real unrelated rule, so both snapshots describe kernel state
	// and cleanup must restore its exact order rather than just an empty table.
	must("iptables", "-w", "-t", "raw", "-A", "OUTPUT", "-p", "udp", "--dport", "9", "-m", "comment", "--comment", "acceptance-keep", "-j", "RETURN")
	before := normalizeAcceptanceSnapshot(must("iptables-save"))
	ranges := s.endpointRanges()
	r := &hostRouter{run: commandOutput, port: DefaultPort, protected: ranges[:]}
	if err := r.installTransportBoundary(); err != nil {
		t.Fatal(err)
	}
	installed := normalizeAcceptanceSnapshot(must("iptables-save"))
	if err := r.installTransportBoundary(); err != nil {
		t.Fatal(err)
	}
	if normalizeAcceptanceSnapshot(must("iptables-save")) != installed {
		t.Fatal("repeated guard installation changed firewall")
	}
	bus := eventbus.New()
	defer bus.Close()
	monitor, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	for _, tc := range []struct {
		name, source, dest string
		marked, allow      bool
	}{
		{"public-underlay", "198.18.0.1:41641", "192.168.64.3:18080", true, true},
		{"different-peer-port", "198.18.0.1:41641", "10.42.0.1:18080", false, false},
		{"rebound-marked-port", "198.18.0.1:0", "10.42.0.1:18080", true, false},
		{"service-recursion", "198.18.0.1:0", "10.43.0.10:18080", true, false},
		{"overlay-recursion", "198.18.0.1:0", "100.64.0.1:18080", true, false},
		{"incoming-disco-from-pod", "10.42.0.1:0", "198.18.0.1:41641", false, false},
		{"ordinary-pod-udp", "10.42.0.1:0", "198.18.0.1:18080", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest, err := net.ListenPacket("udp4", tc.dest)
			if err != nil {
				t.Fatal(err)
			}
			defer dest.Close()
			lc := &net.ListenConfig{}
			if tc.marked {
				// The actual upstream socket constructor used by magicsock,
				// including when requested port binding falls back to port 0.
				lc = netns.Listener(logger.Discard, monitor)
			}
			source, err := lc.ListenPacket(context.Background(), "udp4", tc.source)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			_, sendErr := source.WriteTo([]byte("endpoint-boundary"), dest.LocalAddr())
			_ = dest.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			b := make([]byte, 64)
			n, _, receiveErr := dest.ReadFrom(b)
			if tc.allow && (sendErr != nil || receiveErr != nil || string(b[:n]) != "endpoint-boundary") {
				t.Fatalf("allowed packet failed: send=%v receive=%v", sendErr, receiveErr)
			}
			if !tc.allow && receiveErr == nil {
				t.Fatal("recursive transport reached its destination")
			}
		})
	}
	if err := r.removeTransportBoundary(); err != nil {
		t.Fatal(err)
	}
	if err := r.removeTransportBoundary(); err != nil {
		t.Fatal("repeated exact cleanup:", err)
	}
	if after := normalizeAcceptanceSnapshot(must("iptables-save")); after != before {
		t.Fatalf("guard cleanup changed unrelated firewall state\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
