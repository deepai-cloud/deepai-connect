//go:build linux

package hostnet

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// All interfaces, forwarding and firewall changes are confined to three new
// namespaces. Actual UDP delivery tests LOCAL scoping and ingress enforcement.
func TestLinuxVXLANBoundary(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" {
		t.Skip("requires explicitly opted-in Linux namespace test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	must := func(args ...string) string {
		t.Helper()
		b, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, b)
		}
		return string(b)
	}
	for _, args := range [][]string{{"ip", "-json", "route", "show", "table", "all"}, {"ip", "-json", "rule", "show"}, {"iptables-save"}} {
		before := normalizeAcceptanceSnapshot(must(args...))
		t.Cleanup(func() {
			b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			if err != nil || normalizeAcceptanceSnapshot(string(b)) != before {
				t.Errorf("caller namespace changed: %v: %v", args, err)
			}
		})
	}
	prefix := fmt.Sprintf("dc-vxlan-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	a, b, c := prefix+"a", prefix+"b", prefix+"c"
	for _, ns := range []string{a, b, c} {
		must("ip", "netns", "add", ns)
		t.Cleanup(func() {
			if out, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput(); err != nil {
				t.Errorf("remove namespace %s: %v %s", ns, err, out)
			}
		})
		must("ip", "-n", ns, "link", "set", "lo", "up")
	}
	ns := func(which string, args ...string) string {
		t.Helper()
		return must(append([]string{"ip", "netns", "exec", which}, args...)...)
	}
	ns(a, "ip", "link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", b)
	ns(a, "ip", "link", "add", "deepai0", "type", "veth", "peer", "name", "eth0", "netns", c)
	for _, link := range []struct{ ns, iface, address string }{{a, "eth0", "198.18.1.1/24"}, {b, "eth0", "198.18.1.2/24"}, {a, "deepai0", "100.96.0.1/24"}, {c, "eth0", "100.96.0.2/24"}} {
		ns(link.ns, "ip", "address", "add", link.address, "broadcast", "+", "dev", link.iface)
		ns(link.ns, "ip", "link", "set", link.iface, "up")
	}
	ns(b, "ip", "route", "add", "100.96.0.0/24", "via", "198.18.1.1")
	ns(b, "ip", "route", "add", "224.0.0.0/4", "dev", "eth0")
	ns(b, "ip", "address", "add", "100.96.0.77/32", "dev", "lo")
	ns(c, "ip", "route", "add", "198.18.1.0/24", "via", "100.96.0.1")
	ns(a, "sysctl", "-w", "net.ipv4.ip_forward=1")
	// A raw ACCEPT already present must not bypass the listener boundary.
	ns(a, "iptables", "-w", "-t", "raw", "-A", "PREROUTING", "-s", "198.18.1.2", "-j", "ACCEPT")
	run := func(name string, args ...string) ([]byte, error) {
		out, err := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", a, name}, args...)...).CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("%s %v: %w: %s", name, args, err, out)
		}
		return out, nil
	}
	if err := configureVXLANBoundary(run, "deepai0"); err != nil {
		t.Fatal(err)
	}
	before := ns(a, "iptables-save")
	if err := configureVXLANBoundary(run, "deepai0"); err != nil {
		t.Fatal(err)
	}
	if after := ns(a, "iptables-save"); normalizeAcceptanceSnapshot(after) != normalizeAcceptanceSnapshot(before) {
		t.Fatal("restarted boundary changed firewall configuration")
	}
	// Duplicate and moved hooks are reconciled without disturbing the other
	// owner's rule. The unit test also checks every intermediate rule state.
	ns(a, "iptables", "-w", "-t", "raw", "-A", "PREROUTING", "-p", "udp", "-m", "udp", "--dport", "8472", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DEEPAI-VXLAN")
	if err := configureVXLANBoundary(run, "deepai0"); err != nil {
		t.Fatal(err)
	}
	if after := ns(a, "iptables-save"); normalizeAcceptanceSnapshot(after) != normalizeAcceptanceSnapshot(before) {
		t.Fatal("duplicate reconciliation changed unrelated rules")
	}
	// K3s can prepend filter INPUT rules after the agent starts. Local-delivery
	// enforcement in mangle must still run before even an unconditional ACCEPT.
	ns(a, "iptables", "-w", "-t", "filter", "-I", "INPUT", "-j", "ACCEPT")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	listen := func(which, filename string) string {
		t.Helper()
		path := filepath.Join(dir, filename)
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", which, exe, "-test.run=^TestLinuxVXLANUDPHelper$")
		cmd.Env = append(os.Environ(), "DEEPAI_VXLAN_HELPER=listen", "DEEPAI_VXLAN_OUTPUT="+path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(path); err == nil {
				return path
			}
			if time.Now().After(deadline) {
				t.Fatal("UDP helper did not become ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	local, forwarded := listen(a, "local"), listen(c, "forwarded")
	send := func(which, dst, source, payload string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", which, exe, "-test.run=^TestLinuxVXLANUDPHelper$")
		cmd.Env = append(os.Environ(), "DEEPAI_VXLAN_HELPER=send", "DEEPAI_VXLAN_DST="+dst, "DEEPAI_VXLAN_SOURCE="+source, "DEEPAI_VXLAN_PAYLOAD="+payload)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("send UDP: %v %s", err, out)
		}
	}
	send(b, "198.18.1.1:8472", "", "blocked-underlay")
	send(b, "100.96.0.1:8472", "", "blocked-overlay-destination")
	send(b, "198.18.1.1:8472", "100.96.0.77", "blocked-forged-overlay-source")
	send(b, "198.18.1.255:8472", "", "blocked-broadcast")
	send(b, "224.0.0.1:8472", "", "blocked-multicast")
	send(c, "100.96.0.1:8472", "", "allowed-overlay")
	send(b, "100.96.0.2:8472", "", "allowed-forwarded")
	time.Sleep(150 * time.Millisecond)
	read := func(path string) string {
		t.Helper()
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	if got := read(local); got != "allowed-overlay\n" {
		t.Fatalf("local listener ingress boundary failed: %q", got)
	}
	if got := read(forwarded); got != "allowed-forwarded\n" {
		t.Fatalf("unrelated forwarded VXLAN was blocked: %q", got)
	}
	counters := ns(a, "iptables", "-w", "-t", "raw", "-L", "DEEPAI-VXLAN", "-n", "-v", "-x")
	if !strings.Contains(counters, "DROP") {
		t.Fatal("missing boundary counter")
	}
	localCounters := ns(a, "iptables", "-w", "-t", "mangle", "-L", "DEEPAI-VXLAN-IN", "-n", "-v", "-x")
	t.Logf("local underlay including forged source/broadcast/multicast blocked; overlay allowed; forwarded UDP8472 preserved; repeat installation and duplicates preserved unrelated rules\n%s\n%s", counters, localCounters)
}

func TestLinuxVXLANUDPHelper(t *testing.T) {
	switch os.Getenv("DEEPAI_VXLAN_HELPER") {
	case "listen":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 8472})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		f, err := os.OpenFile(os.Getenv("DEEPAI_VXLAN_OUTPUT"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		_ = conn.SetReadDeadline(time.Now().Add(40 * time.Second))
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintln(f, string(buf[:n])); err != nil {
				t.Fatal(err)
			}
		}
	case "send":
		dst, err := net.ResolveUDPAddr("udp4", os.Getenv("DEEPAI_VXLAN_DST"))
		if err != nil {
			t.Fatal(err)
		}
		var source *net.UDPAddr
		if ip := os.Getenv("DEEPAI_VXLAN_SOURCE"); ip != "" {
			source = &net.UDPAddr{IP: net.ParseIP(ip)}
		}
		conn, err := net.DialUDP("udp4", source, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		}); err != nil {
			t.Fatal(err)
		}
		if sockErr != nil {
			t.Fatal(sockErr)
		}
		if _, err := conn.Write([]byte(os.Getenv("DEEPAI_VXLAN_PAYLOAD"))); err != nil {
			t.Fatal(err)
		}
	default:
		t.Skip("subprocess helper")
	}
}
