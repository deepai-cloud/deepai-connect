//go:build linux

package hostnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Reproduce a parent NAT/VPN migration that the guest cannot observe: its
// interfaces and routes stay unchanged, old TCP tuples silently stop working,
// UDP is unavailable, but new TCP connections can reach control and the relay.
func TestLinuxStaleNATPathRecovery(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" {
		t.Skip("requires explicitly opted-in Linux namespace test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	interrupt, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupt, 3*time.Minute)
	defer cancel()
	h := &linuxAcceptance{t: t, ctx: ctx, root: t.TempDir()}
	h.assertHostUnchangedOnCleanup()
	h.createTopology()
	h.start("fabric", "derp")
	var dm tailcfg.DERPMap
	h.awaitJSON(filepath.Join(h.dir("fabric"), "derp.json"), &dm)
	a, _ := h.makeState("a", 1)
	b, _ := h.makeState("b", 2)
	for _, s := range []*State{a, b} {
		s.DERPMap = &dm
		s.Self.HomeDERP = 1
		s.Self.Hostinfo = (&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 1}}).View()
	}
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	for i, name := range []string{"a", "b"} {
		if err := SaveState(h.dir(name), []*State{a, b}[i]); err != nil {
			t.Fatal(err)
		}
		// Only this fixture's guest traffic is blocked; the caller and live
		// Connect/K3s processes retain their own namespaces and connections.
		h.ns(name, "iptables", "-w", "-I", "OUTPUT", "1", "-p", "udp", "--sport", "41641", "-j", "DROP")
	}
	h.start("fabric", "control-recovery")
	var control key.MachinePublic
	h.awaitJSON(filepath.Join(h.dir("fabric"), "control-key.json"), &control)
	for _, name := range []string{"a", "b"} {
		h.start(name, "agent-recovery")
		h.ready(name)
	}
	h.awaitHTTP("a", "http://100.64.0.2:18080/", "100.64.0.1")
	h.bulkTransfer("a", "http://100.64.0.2:18080/bulk", "", acceptanceBulkPayload())
	initialPort := h.relayTCPPort("a")
	beforeAddress := h.ns("a", "ip", "-json", "addr", "show", "dev", "eth0")
	beforeDefault := h.ns("a", "ip", "route", "show", "default")

	// A coordinator transport outage alone must not close a healthy relay.
	controlDrop := []string{"OUTPUT", "-d", "198.18.0.254", "-p", "tcp", "--dport", "8080", "-j", "DROP"}
	h.ns("a", append([]string{"iptables", "-w", "-I"}, controlDrop...)...)
	h.awaitRecoveryLog("coordinator refresh failed", 8*time.Second)
	h.bulkTransfer("a", "http://100.64.0.2:18080/bulk", "", acceptanceBulkPayload())
	h.ns("a", append([]string{"iptables", "-w", "-D"}, controlDrop...)...)
	h.awaitRecoveryLog("post-rebind ping of DERP region 1 okay", 10*time.Second)
	if port := h.relayTCPPort("a"); port != initialPort {
		t.Fatalf("healthy relay was replaced: local TCP port %s -> %s", initialPort, port)
	}
	t.Log("PASS: timed-out control followed by authenticated map preserved the healthy DERP TCP connection")

	// A new connection must work while the pre-migration relay connection is
	// silently blackholed in both directions. Keeping that exact tuple blocked
	// throughout recovery proves we replaced it instead of lifting the fault.
	h.ns("a", "iptables", "-w", "-I", "OUTPUT", "1", "-d", "198.18.0.254", "-p", "tcp", "--sport", initialPort, "--dport", "8443", "-j", "DROP")
	h.ns("a", "iptables", "-w", "-I", "INPUT", "1", "-s", "198.18.0.254", "-p", "tcp", "--sport", "8443", "--dport", initialPort, "-j", "DROP")
	h.ns("a", append([]string{"iptables", "-w", "-I"}, controlDrop...)...)
	// Start this window after the healthy recovery; require a later timeout.
	time.Sleep(4 * time.Second)
	if out, err := h.request("a", "http://100.64.0.2:18080/"); err == nil {
		t.Fatalf("stale relay unexpectedly carried data before control recovery: %s", out)
	}
	h.ns("a", "curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "3", "https://198.18.0.254:8443/")
	if port := h.relayTCPPort("a"); port != initialPort {
		t.Fatalf("relay reconnected while control was unavailable: %s -> %s", initialPort, port)
	}
	h.ns("a", append([]string{"iptables", "-w", "-D"}, controlDrop...)...)
	start := time.Now()
	h.bulkTransfer("a", "http://100.64.0.2:18080/bulk", "", acceptanceBulkPayload())
	elapsed := time.Since(start)
	if elapsed >= 15*time.Second {
		t.Fatalf("stale path recovery took %s", elapsed)
	}
	if port := h.relayTCPPort("a"); port == initialPort {
		t.Fatal("payload succeeded without replacing the blackholed relay connection")
	}
	h.awaitRecoveryLog("rebind-ping-fail", 3*time.Second)
	h.bulkTransfer("b", "http://100.64.0.1:18080/bulk", "", acceptanceBulkPayload())
	if beforeAddress != h.ns("a", "ip", "-json", "addr", "show", "dev", "eth0") || beforeDefault != h.ns("a", "ip", "route", "show", "default") {
		t.Fatal("test changed the guest interface or default route")
	}
	h.awaitRelayTraffic()
	t.Logf("PASS: stale relay tuple remained blocked; fresh authenticated map recovered 256KiB hashed TCP transfer in %s instead of the upstream 120-second receive timeout", elapsed.Round(time.Millisecond))
}

func (h *linuxAcceptance) relayTCPPort(name string) string {
	h.t.Helper()
	out := h.ns(name, "ss", "-Hnt", "state", "established", "(", "dport", "=", ":8443", ")")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		h.t.Fatalf("expected one relay TCP connection: %s", out)
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 4 {
		h.t.Fatalf("invalid relay socket record: %s", out)
	}
	_, port, err := net.SplitHostPort(fields[2])
	if err != nil {
		h.t.Fatal(err)
	}
	return port
}

func (h *linuxAcceptance) awaitRecoveryLog(needle string, duration time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) && h.ctx.Err() == nil {
		if b, err := os.ReadFile(filepath.Join(h.dir("a"), "process.log")); err == nil && strings.Contains(string(b), needle) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatalf("agent never reported %q", needle)
}

func acceptanceRecoveryControl(t *testing.T, ctx context.Context, dir string) {
	control, err := coordinator.New(ctx, coordinator.Config{Store: &coordinator.MemoryStore{}})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	err = control.Update(ctx, func(state *coordinator.State) error {
		for _, name := range []string{"a", "b"} {
			s, err := LoadState(filepath.Join(filepath.Dir(dir), name))
			if err != nil {
				return err
			}
			state.Network, state.Policy, state.DERPMap = s.HostCIDR.String(), s.PacketFilter, s.DERPMap
			n := &coordinator.Node{ID: uint64(s.Self.ID), MachineKey: s.Self.Machine.String(), NodeKey: s.Self.Key.String(), DiscoKey: s.Self.DiscoKey.String(), Hostname: name, Role: "worker", Addresses: slices.Clone(s.Self.Addresses), Hostinfo: s.Self.Hostinfo.AsStruct()}
			if err := coordinator.AllocateNode(state, n); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "198.18.0.254:8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: control.Handler(), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	if err := writeAcceptanceJSON(filepath.Join(dir, "control-key.json"), control.PublicKey()); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
}

func acceptanceRecoveryFetch(ctx context.Context, dir string, id *Identity, state *State, endpoints []netip.AddrPort) (*tailcfg.MapResponse, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(dir), "fabric", "control-key.json"))
	if err != nil {
		return nil, err
	}
	var public key.MachinePublic
	if err := json.Unmarshal(b, &public); err != nil || public.IsZero() {
		return nil, errors.New("missing test coordinator identity")
	}
	client := coordinator.Client{ServerURL: "http://198.18.0.254:8080", ServerKey: public, MachineKey: id.Machine}
	// Only the fixture shortens the network request deadline. Production uses
	// the same classified transport error with its existing fifteen seconds.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	m, err := client.Map(ctx, tailcfg.MapRequest{NodeKey: id.Node.Public(), DiscoKey: id.Disco.Public(), Endpoints: endpoints, Hostinfo: state.Self.Hostinfo.AsStruct()})
	if err != nil {
		return nil, fmt.Errorf("authenticated fixture map: %w", err)
	}
	return m, nil
}
