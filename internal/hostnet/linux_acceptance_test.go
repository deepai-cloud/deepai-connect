//go:build linux

package hostnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// This test is intentionally opt-in. Every network mutation runs in a newly
// created namespace; no route, firewall rule, forwarding setting, or interface
// is installed in the caller's network namespace. See linux-acceptance.md.
func TestLinuxNamespaceAcceptance(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" {
		t.Skip("set DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns on a Linux test host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("namespace acceptance requires root")
	}
	for _, command := range []string{"ip", "iptables", "iptables-save", "sysctl", "curl"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Fatal(err)
	}
	interrupt, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupt, 4*time.Minute)
	defer cancel()
	h := &linuxAcceptance{t: t, ctx: ctx, root: t.TempDir()}
	h.assertHostUnchangedOnCleanup()
	h.createTopology()
	a, aid := h.makeState("a", 1)
	b, bid := h.makeState("b", 2)
	a.Self.AllowedIPs = append(a.Self.AllowedIPs, netip.MustParsePrefix("10.42.1.0/24"))
	b.Self.AllowedIPs = append(b.Self.AllowedIPs, netip.MustParsePrefix("10.42.2.0/24"))
	a.PodRoutes, b.PodRoutes = slices.Clone(a.Self.AllowedIPs[1:]), slices.Clone(b.Self.AllowedIPs[1:])
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	a.DirectHubEndpoints[b.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("198.18.0.2:41641")}
	b.DirectHubEndpoints[a.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("198.18.0.1:41641")}
	for _, item := range []struct {
		name string
		s    *State
		id   *Identity
	}{{"a", a, aid}, {"b", b, bid}} {
		if err := item.s.Validate(item.id, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := SaveState(h.dir(item.name), item.s); err != nil {
			t.Fatal(err)
		}
	}
	identityA := h.readFile(filepath.Join(h.dir("a"), "identity.json"))
	identityB := h.readFile(filepath.Join(h.dir("b"), "identity.json"))
	pa, pb := h.start("a", "agent"), h.start("b", "agent")
	h.start("pod", "http")
	h.ready("a")
	h.ready("b")
	h.awaitHTTP("a", "http://100.64.0.2:18080/", "100.64.0.1")
	h.awaitHTTP("pod", "http://100.64.0.1:18080/", "10.42.2.5")
	h.awaitHTTP("a", "http://10.42.2.5:18080/", "100.64.0.1")
	h.assertCNI()
	t.Log("PASS: real TUN host traffic, unchanged pod source and reply route, CNI route/firewall coexistence")

	// Both agents stop before either restarts. The coordinator and DERP are
	// absent throughout this phase; only private identity + trusted cache exist.
	pa.kill()
	pb.kill()
	pa, pb = h.start("a", "agent"), h.start("b", "agent")
	h.ready("a")
	h.ready("b")
	h.awaitHTTP("a", "http://100.64.0.2:18080/", "100.64.0.1")
	h.awaitHTTP("pod", "http://100.64.0.1:18080/", "10.42.2.5")
	if string(identityA) != string(h.readFile(filepath.Join(h.dir("a"), "identity.json"))) || string(identityB) != string(h.readFile(filepath.Join(h.dir("b"), "identity.json"))) {
		t.Fatal("cached restart changed local private identities")
	}
	h.assertCNI()
	t.Log("PASS: simultaneous cached restart without coordinator, DNS, Kubernetes, or DERP")

	// A minimal kube-router-style chain tests the actual kernel verdict rather
	// than asserting command syntax. Install it after Connect and retain it
	// through a crash/restart, covering both service startup orders.
	h.ns("b", "iptables", "-w", "-N", "KUBE-ROUTER-FORWARD")
	// Ingress policy must permit replies to pod-initiated connections, as the
	// real kube-router controller does before evaluating new ingress flows.
	h.ns("b", "iptables", "-w", "-A", "KUBE-ROUTER-FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
	h.ns("b", "iptables", "-w", "-A", "KUBE-ROUTER-FORWARD", "-s", "100.64.0.1/32", "-d", "10.42.2.5/32", "-j", "DROP")
	h.ns("b", "iptables", "-w", "-I", "FORWARD", "1", "-j", "KUBE-ROUTER-FORWARD")
	h.assertHTTPDenied("a", "http://10.42.2.5:18080/")
	pb.kill()
	pb = h.start("b", "agent")
	h.ready("b")
	h.awaitHTTP("a", "http://100.64.0.2:18080/", "100.64.0.1")
	h.awaitHTTP("pod", "http://100.64.0.1:18080/", "10.42.2.5")
	h.assertHTTPDenied("a", "http://10.42.2.5:18080/")
	h.ns("b", "iptables", "-w", "-D", "KUBE-ROUTER-FORWARD", "-s", "100.64.0.1/32", "-d", "10.42.2.5/32", "-j", "DROP")
	h.awaitHTTP("a", "http://10.42.2.5:18080/", "100.64.0.1")
	t.Log("PASS: kernel NetworkPolicy deny remains effective after agent restart, allowed traffic continues")

	// Bring up an isolated TLS relay, block actual underlay WireGuard UDP, and
	// propagate the live NetInfo reports as the coordinator normally would.
	h.start("fabric", "derp")
	var dm tailcfg.DERPMap
	h.awaitJSON(filepath.Join(h.dir("fabric"), "derp.json"), &dm)
	a.DERPMap, b.DERPMap = &dm, &dm
	for _, name := range []string{"a", "b"} {
		h.ns(name, "iptables", "-w", "-I", "OUTPUT", "1", "-p", "udp", "--sport", "41641", "-j", "DROP")
	}
	h.update("a", a)
	h.update("b", b)
	infoA, infoB := h.awaitDERP("a"), h.awaitDERP("b")
	a.Self.HomeDERP, b.Self.HomeDERP = infoA.PreferredDERP, infoB.PreferredDERP
	a.Self.Hostinfo, b.Self.Hostinfo = (&tailcfg.Hostinfo{NetInfo: infoA}).View(), (&tailcfg.Hostinfo{NetInfo: infoB}).View()
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	h.update("a", a)
	h.update("b", b)
	h.awaitHTTP("a", "http://100.64.0.2:18080/", "100.64.0.1")
	h.awaitHTTP("pod", "http://100.64.0.1:18080/", "10.42.2.5")
	metrics := h.awaitRelayTraffic()
	for _, name := range []string{"a", "b"} {
		out := h.ns(name, "iptables", "-w", "-v", "-x", "-n", "-L", "OUTPUT")
		if !acceptanceHasDroppedPackets(out) {
			t.Fatalf("direct-UDP fault rule did not drop packets: %s", out)
		}
		t.Logf("%s isolated OUTPUT counters:\n%s", name, out)
	}
	h.assertCNI()
	t.Logf("PASS: real TLS DERP fallback with direct UDP blocked; relay received %.0f and sent %.0f bytes", metrics["bytes_received"], metrics["bytes_sent"])
}

type linuxAcceptance struct {
	t     *testing.T
	ctx   context.Context
	root  string
	names map[string]string
}

func (h *linuxAcceptance) run(args ...string) string {
	h.t.Helper()
	b, err := exec.CommandContext(h.ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		h.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, b)
	}
	return string(b)
}

func (h *linuxAcceptance) ns(name string, args ...string) string {
	h.t.Helper()
	return h.run(append([]string{"ip", "netns", "exec", h.names[name]}, args...)...)
}

func (h *linuxAcceptance) dir(name string) string { return filepath.Join(h.root, name) }

func (h *linuxAcceptance) readFile(path string) []byte {
	h.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

func (h *linuxAcceptance) createTopology() {
	h.names = make(map[string]string)
	prefix := fmt.Sprintf("dc-accept-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	for _, name := range []string{"a", "b", "fabric", "pod"} {
		ns := prefix + "-" + name
		h.run("ip", "netns", "add", ns)
		h.names[name] = ns
		h.t.Cleanup(func() {
			b, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput()
			if err != nil {
				h.t.Errorf("remove test namespace %s: %v: %s", ns, err, b)
			}
		})
		if err := os.Mkdir(h.dir(name), 0700); err != nil {
			h.t.Fatal(err)
		}
		h.ns(name, "ip", "link", "set", "lo", "up")
	}
	h.t.Logf("Temporary test namespaces: %v", h.names)
	h.ns("fabric", "ip", "link", "add", "br0", "type", "bridge")
	h.ns("fabric", "ip", "address", "add", "198.18.0.254/24", "dev", "br0")
	h.ns("fabric", "ip", "link", "set", "br0", "up")
	for i, name := range []string{"a", "b"} {
		h.ns(name, "ip", "link", "add", "eth0", "type", "veth", "peer", "name", "v"+name, "netns", h.names["fabric"])
		h.ns(name, "ip", "address", "add", fmt.Sprintf("198.18.0.%d/24", i+1), "dev", "eth0")
		h.ns(name, "ip", "link", "set", "eth0", "up")
		h.ns(name, "ip", "route", "add", "default", "via", "198.18.0.254")
		h.ns("fabric", "ip", "link", "set", "v"+name, "master", "br0")
		h.ns("fabric", "ip", "link", "set", "v"+name, "up")
		h.ns(name, "iptables", "-w", "-P", "FORWARD", "DROP")
		h.ns(name, "iptables", "-w", "-N", "ACCEPTANCE-KEEP")
		h.ns(name, "iptables", "-w", "-A", "ACCEPTANCE-KEEP", "-j", "RETURN")
		h.ns(name, "iptables", "-w", "-A", "OUTPUT", "-j", "ACCEPTANCE-KEEP")
		h.ns(name, "ip", "route", "add", "blackhole", "198.19.255.0/24", "proto", "99")
	}
	h.ns("b", "ip", "link", "add", "cni0", "type", "bridge")
	h.ns("b", "ip", "address", "add", "10.42.2.1/24", "dev", "cni0")
	h.ns("b", "ip", "link", "set", "cni0", "up")
	h.ns("b", "ip", "link", "add", "pod0", "type", "veth", "peer", "name", "eth0", "netns", h.names["pod"])
	h.ns("b", "ip", "link", "set", "pod0", "master", "cni0")
	h.ns("b", "ip", "link", "set", "pod0", "up")
	h.ns("pod", "ip", "address", "add", "10.42.2.5/24", "dev", "eth0")
	h.ns("pod", "ip", "link", "set", "eth0", "up")
	h.ns("pod", "ip", "route", "add", "default", "via", "10.42.2.1")
	// Represents an existing CNI route at exactly an advertised remote prefix.
	// The engine must retain it instead of claiming/replacing it as proto 186.
	h.ns("b", "ip", "route", "add", "10.42.1.0/24", "via", "198.18.0.1", "proto", "99")
}

func (h *linuxAcceptance) makeState(name string, number uint8) (*State, *Identity) {
	s, _ := testState(h.t, number)
	id, err := LoadOrCreateIdentity(h.dir(name))
	if err != nil {
		h.t.Fatal(err)
	}
	s.Self.Machine, s.Self.Key, s.Self.DiscoKey = id.Machine.Public(), id.Node.Public(), id.Disco.Public()
	s.PacketFilter = []tailcfg.FilterRule{{SrcIPs: []string{s.HostCIDR.String(), s.PodCIDR.String()}, DstPorts: []tailcfg.NetPortRange{
		{IP: s.HostCIDR.String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}},
		{IP: s.PodCIDR.String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}},
	}}}
	return s, id
}

type acceptanceProcess struct {
	t    *testing.T
	cmd  *exec.Cmd
	done chan error
	dead bool
}

func (p *acceptanceProcess) kill() {
	p.t.Helper()
	if p.dead {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
		p.dead = true
	case <-time.After(10 * time.Second):
		p.t.Error("test namespace process did not exit after SIGKILL")
	}
}

func (h *linuxAcceptance) start(name, role string) *acceptanceProcess {
	h.t.Helper()
	binary, err := os.Executable()
	if err != nil {
		h.t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(h.dir(name), "process.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		h.t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", h.names[name], binary, "-test.run=^TestLinuxNamespaceProcess$", "-test.v", "-test.timeout=5m")
	cmd.Env = slices.DeleteFunc(os.Environ(), func(v string) bool {
		k, _, _ := strings.Cut(v, "=")
		return strings.HasSuffix(strings.ToUpper(k), "_PROXY")
	})
	cmd.Env = append(cmd.Env, "NO_PROXY=*", "DEEPAI_CONNECT_NETNS_ROLE="+role, "DEEPAI_CONNECT_NETNS_DIR="+h.dir(name))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		h.t.Fatal(err)
	}
	p := &acceptanceProcess{t: h.t, cmd: cmd, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	h.t.Cleanup(func() {
		if !p.dead {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-p.done:
				p.dead = true
			case <-time.After(5 * time.Second):
				p.kill()
			}
		}
		_ = log.Close()
		if h.t.Failed() {
			h.t.Logf("%s process log:\n%s", name, h.readFile(filepath.Join(h.dir(name), "process.log")))
		}
	})
	return p
}

func (h *linuxAcceptance) ready(name string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
	defer cancel()
	if err := WaitReady(ctx, h.dir(name)); err != nil {
		h.t.Fatalf("%s agent startup: %v", name, err)
	}
}

func (h *linuxAcceptance) update(name string, s *State) {
	h.t.Helper()
	// Local fixture updates do not extend trusted cache expiry.
	s.UpdatedAt = time.Now()
	if err := Update(h.ctx, h.dir(name), s); err != nil {
		h.t.Fatal(err)
	}
}

func (h *linuxAcceptance) request(name, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(h.ctx, 4*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "ip", "netns", "exec", h.names[name], "curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "3", url).CombinedOutput()
}

func (h *linuxAcceptance) awaitHTTP(name, url, wantSource string) {
	h.t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	var last []byte
	var err error
	for h.ctx.Err() == nil && time.Now().Before(deadline) {
		last, err = h.request(name, url)
		if err == nil {
			if strings.TrimSpace(string(last)) != wantSource {
				h.t.Fatalf("%s observed source %q, want %s", url, last, wantSource)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	h.t.Fatalf("%s -> %s never became reachable: %v: %s", name, url, err, last)
}

func (h *linuxAcceptance) assertHTTPDenied(name, url string) {
	h.t.Helper()
	if b, err := h.request(name, url); err == nil {
		h.t.Fatalf("NetworkPolicy denied request reached its pod: %s", b)
	}
}

func (h *linuxAcceptance) awaitJSON(path string, dst any) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for h.ctx.Err() == nil && time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(b, dst) == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("no valid process report at %s", path)
}

func (h *linuxAcceptance) awaitDERP(name string) *tailcfg.NetInfo {
	h.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for h.ctx.Err() == nil && time.Now().Before(deadline) {
		var info tailcfg.NetInfo
		b, err := os.ReadFile(filepath.Join(h.dir(name), "netinfo.json"))
		if err == nil && json.Unmarshal(b, &info) == nil && info.PreferredDERP != 0 {
			return &info
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("%s did not discover an available DERP relay", name)
	return nil
}

func (h *linuxAcceptance) awaitRelayTraffic() map[string]float64 {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.ctx.Err() == nil && time.Now().Before(deadline) {
		var metrics map[string]float64
		b, err := os.ReadFile(filepath.Join(h.dir("fabric"), "metrics.json"))
		if err == nil && json.Unmarshal(b, &metrics) == nil && metrics["bytes_received"] > 0 && metrics["bytes_sent"] > 0 {
			return metrics
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatal("relay did not report carrying encrypted packets")
	return nil
}

func acceptanceHasDroppedPackets(s string) bool {
	for line := range strings.SplitSeq(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "DROP" {
			continue
		}
		packets, err := strconv.ParseUint(fields[0], 10, 64)
		if err == nil && packets > 0 {
			return true
		}
	}
	return false
}

func (h *linuxAcceptance) assertCNI() {
	h.t.Helper()
	for _, name := range []string{"a", "b"} {
		h.ns(name, "iptables", "-w", "-C", "OUTPUT", "-j", "ACCEPTANCE-KEEP")
		h.ns(name, "iptables", "-w", "-C", "ACCEPTANCE-KEEP", "-j", "RETURN")
		if !strings.Contains(h.ns(name, "ip", "-N", "route", "show", "exact", "198.19.255.0/24"), "proto 99") {
			h.t.Fatal("unrelated route was removed")
		}
		if !strings.Contains(h.ns(name, "ip", "route", "show", "default"), "via 198.18.0.254 dev eth0") {
			h.t.Fatal("underlay default route was replaced")
		}
	}
	if !strings.Contains(h.ns("b", "ip", "-N", "route", "show", "exact", "10.42.1.0/24"), "proto 99") {
		h.t.Fatal("Connect replaced an existing CNI route")
	}
	if !strings.Contains(h.ns("b", "ip", "route", "show", "exact", "10.42.2.0/24"), "dev cni0") {
		h.t.Fatal("local CNI route disappeared")
	}
}

func (h *linuxAcceptance) assertHostUnchangedOnCleanup() {
	for _, args := range [][]string{{"ip", "-json", "route", "show", "table", "all"}, {"ip", "-json", "rule", "show"}, {"iptables-save"}} {
		before := normalizeAcceptanceSnapshot(h.run(args...))
		h.t.Cleanup(func() {
			b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			after := normalizeAcceptanceSnapshot(string(b))
			if err != nil || after != before {
				h.t.Errorf("caller namespace changed during acceptance (%v); inspect concurrent host changes: %v\nbefore: %s\nafter: %s", args, err, before, after)
			}
		})
	}
}

func normalizeAcceptanceSnapshot(s string) string {
	var entries []map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &entries) == nil {
		// IPv6 Router Advertisement route lifetimes count down even when no
		// configuration changes. Keep every route and all forwarding/ownership
		// fields; normalize only this elapsed-time field and JSON formatting.
		for _, entry := range entries {
			delete(entry, "expires")
		}
		b, _ := json.Marshal(entries)
		return string(b)
	}
	var lines []string
	for line := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		// iptables-save includes live chain counters even without -c. Keep
		// chain names and policies, and compare every ordered rule unchanged.
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line)
			if len(fields) == 3 && strings.HasPrefix(fields[2], "[") && strings.HasSuffix(fields[2], "]") {
				line = strings.Join(fields[:2], " ")
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func TestLinuxRouteSnapshotIgnoresExpiryButKeepsRoute(t *testing.T) {
	a := `[{"dst":"default","gateway":"fe80::1","dev":"eth0","protocol":"ra","expires":8999}]`
	b := strings.Replace(a, "8999", "8980", 1)
	if normalizeAcceptanceSnapshot(a) != normalizeAcceptanceSnapshot(b) {
		t.Fatal("route lifetime countdown changed the configuration snapshot")
	}
	for _, changed := range []string{
		strings.Replace(b, "eth0", "deepai0", 1),
		strings.Replace(b, "fe80::1", "fe80::2", 1),
		strings.Replace(b, `"ra"`, `"186"`, 1),
		`[]`,
	} {
		if normalizeAcceptanceSnapshot(a) == normalizeAcceptanceSnapshot(changed) {
			t.Fatal("snapshot normalization hid a changed or removed route")
		}
	}
}

func TestLinuxFirewallSnapshotIgnoresCountersButKeepsPolicy(t *testing.T) {
	a := "# Generated at one time\n*filter\n:FORWARD DROP [10:100]\n-A FORWARD -j FIRST\n-A FORWARD -j SECOND\nCOMMIT\n"
	b := "# Generated later\n*filter\n:FORWARD DROP [11:110]\n-A FORWARD -j FIRST\n-A FORWARD -j SECOND\nCOMMIT\n"
	if normalizeAcceptanceSnapshot(a) != normalizeAcceptanceSnapshot(b) {
		t.Fatal("packet counters changed the firewall configuration snapshot")
	}
	for _, changed := range []string{
		strings.Replace(b, ":FORWARD DROP", ":FORWARD ACCEPT", 1),
		strings.Replace(b, "-j FIRST\n-A FORWARD -j SECOND", "-j SECOND\n-A FORWARD -j FIRST", 1),
	} {
		if normalizeAcceptanceSnapshot(a) == normalizeAcceptanceSnapshot(changed) {
			t.Fatal("snapshot normalization hid a policy or rule-order change")
		}
	}
}

// Invoked only as a subprocess inside one of the test's namespaces. Keeping
// engines in separate processes ensures every Go runtime thread inherits the
// intended network namespace; setns on a single goroutine would be unsafe.
func TestLinuxNamespaceProcess(t *testing.T) {
	role, dir := os.Getenv("DEEPAI_CONNECT_NETNS_ROLE"), os.Getenv("DEEPAI_CONNECT_NETNS_DIR")
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" || role == "" || dir == "" {
		t.Skip("namespace acceptance helper")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	switch role {
	case "derp":
		acceptanceDERP(t, ctx, dir)
	case "control-recovery":
		acceptanceRecoveryControl(t, ctx, dir)
	case "agent", "agent-recovery":
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, dir, Options{Logf: t.Logf, PollInterval: time.Second, Fetch: func(fetchCtx context.Context, id *Identity, s *State, ep []netip.AddrPort) (*tailcfg.MapResponse, error) {
				if hi := s.Self.Hostinfo.AsStruct(); hi != nil && hi.NetInfo != nil {
					if err := writeAcceptanceJSON(filepath.Join(dir, "netinfo.json"), hi.NetInfo); err != nil {
						return nil, err
					}
				}
				if role == "agent-recovery" {
					return acceptanceRecoveryFetch(fetchCtx, dir, id, s, ep)
				}
				return nil, errors.New("coordinator intentionally unavailable during namespace acceptance")
			}})
		}()
		ready, stop := context.WithTimeout(ctx, 20*time.Second)
		err := WaitReady(ready, dir)
		if err != nil {
			stop()
			t.Fatal(err)
		}
		status, err := AgentStatus(ready, dir)
		stop()
		if err != nil {
			t.Fatal(err)
		}
		server := acceptanceHTTP(t, status.Address.String()+":18080")
		defer server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
	case "http":
		server := acceptanceHTTP(t, "10.42.2.5:18080")
		defer server.Close()
		<-ctx.Done()
	case "http-vxlan":
		server := acceptanceHTTP(t, "10.42.1.0:18080")
		defer server.Close()
		<-ctx.Done()
	default:
		t.Fatalf("unknown namespace process role %q", role)
	}
}

func acceptanceHTTP(t *testing.T, address string) *http.Server {
	t.Helper()
	l, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bulk" {
			acceptanceBulkHTTP(w, r)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = fmt.Fprintln(w, host)
	})}
	go server.Serve(l)
	return server
}

func acceptanceDERP(t *testing.T, ctx context.Context, dir string) {
	t.Helper()
	relay := derpserver.New(key.NewNode(), logger.Logf(t.Logf))
	defer relay.Close()
	server := httptest.NewUnstartedServer(derpserver.Handler(relay))
	server.Listener.Close()
	l, err := net.Listen("tcp4", "198.18.0.254:8443")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = l
	server.StartTLS()
	defer server.Close()
	certHash := sha256.Sum256(server.Certificate().Raw)
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "namespace-test", Nodes: []*tailcfg.DERPNode{{Name: "namespace-test1", RegionID: 1, HostName: "198.18.0.254", IPv4: "198.18.0.254", IPv6: "none", STUNPort: -1, DERPPort: 8443, CertName: "sha256-raw:" + hex.EncodeToString(certHash[:])}}}}}
	if err := writeAcceptanceJSON(filepath.Join(dir, "derp.json"), dm); err != nil {
		t.Fatal(err)
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Store only numeric transport counters, not client keys or secrets.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(relay.ExpVar(false).String()), &raw); err != nil {
				t.Fatal(err)
			}
			metrics := map[string]json.RawMessage{"bytes_received": raw["bytes_received"], "bytes_sent": raw["bytes_sent"]}
			if err := writeAcceptanceJSON(filepath.Join(dir, "metrics.json"), metrics); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func writeAcceptanceJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return platform.WriteFile(path, b, false)
}
