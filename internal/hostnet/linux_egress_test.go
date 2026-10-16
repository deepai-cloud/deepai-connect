//go:build linux

package hostnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"tailscale.com/wgengine/router"
	"testing"
	"time"
)

// Exercise production policy/NAT install, stop, restore, and explicit disable
// against actual iproute2 output. All kernel changes belong to a new namespace.
func TestLinuxEgressPolicyLifecycle(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" {
		t.Skip("requires explicitly opted-in Linux namespace test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ns := fmt.Sprintf("dc-egress-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	outer := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	}
	if b, err := outer("ip", "netns", "add", ns); err != nil {
		t.Fatalf("create namespace: %v %s", err, b)
	}
	t.Logf("Temporary egress test namespace: %s", ns)
	t.Cleanup(func() {
		if b, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput(); err != nil {
			t.Errorf("remove namespace: %v %s", err, b)
		}
	})
	run := func(name string, args ...string) ([]byte, error) {
		b, err := outer(append([]string{"ip", "netns", "exec", ns, name}, args...)...)
		if err != nil {
			return b, fmt.Errorf("%s %v: %w: %s", name, args, err, b)
		}
		return b, nil
	}
	must := func(name string, args ...string) string {
		t.Helper()
		b, err := run(name, args...)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, iface := range []string{"eth0", "pod0", "deepai0"} {
		must("ip", "link", "add", iface, "type", "dummy")
		must("ip", "link", "set", iface, "up")
	}
	must("ip", "address", "add", "100.96.0.2/32", "dev", "deepai0")
	must("ip", "address", "add", "10.42.1.1/24", "dev", "pod0")
	must("ip", "route", "add", "default", "dev", "eth0", "proto", "99")
	must("sysctl", "-w", "net.ipv4.ip_forward=1")
	must("iptables", "-w", "-t", "nat", "-N", "ACCEPTANCE-KEEP")
	must("iptables", "-w", "-t", "nat", "-A", "POSTROUTING", "-j", "ACCEPTANCE-KEEP")
	must("iptables", "-w", "-t", "nat", "-A", "ACCEPTANCE-KEEP", "-s", "192.0.2.0/24", "-o", "eth0", "-j", "MASQUERADE")
	beforeRules := must("ip", "-json", "-N", "rule", "show")
	beforeMain := must("ip", "-json", "-N", "route", "show", "table", "main")
	beforeNAT := normalizeAcceptanceSnapshot(must("iptables-save", "-t", "nat"))
	protected := []netip.Prefix{netip.MustParsePrefix("100.96.0.0/16"), netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}
	for _, source := range []string{"10.42.1.0/24", "100.96.0.2/32"} {
		r := &hostRouter{run: run, iface: "deepai0", egressAddress: netip.MustParseAddr("100.96.0.2"), egressSources: []netip.Prefix{netip.MustParsePrefix(source)}, protected: protected, cniRanges: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
		probe := []string{"-json", "route", "get", "1.1.1.1", "from", "100.96.0.2"}
		if source == "10.42.1.0/24" {
			probe = []string{"-json", "route", "get", "1.1.1.1", "from", "10.42.1.7", "iif", "pod0"}
		}
		if err := r.setEgress(true); err != nil {
			t.Fatal(err)
		}
		if result := must("ip", probe...); !strings.Contains(result, `"dev":"deepai0"`) {
			t.Fatalf("source %s did not use overlay: %s", source, result)
		}
		// Flannel can take over a previously installed route between maps. A
		// gateway withdrawal/reselection must still apply and preserve that CNI
		// route; an independently deleted route must also withdraw idempotently.
		podRoute := netip.MustParsePrefix("10.42.2.0/24")
		local := []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}
		def := netip.MustParsePrefix("0.0.0.0/0")
		if err := r.Set(&router.Config{LocalAddrs: local, Routes: []netip.Prefix{def, podRoute}}); err != nil {
			t.Fatal(err)
		}
		must("ip", "route", "replace", podRoute.String(), "dev", "pod0", "proto", "99")
		cni := must("ip", "-json", "-N", "route", "show", "exact", podRoute.String())
		if err := r.Set(&router.Config{LocalAddrs: local}); err != nil {
			t.Fatal("CNI takeover prevented gateway withdrawal:", err)
		}
		if b, err := run("ip", probe...); err == nil {
			t.Fatalf("default survived withdrawal after CNI takeover: %s", b)
		}
		if got := must("ip", "-json", "-N", "route", "show", "exact", podRoute.String()); got != cni {
			t.Fatal("CNI route changed during withdrawal")
		}
		if err := r.Set(&router.Config{LocalAddrs: local, Routes: []netip.Prefix{def, podRoute}}); err != nil {
			t.Fatal("CNI takeover prevented gateway reselection:", err)
		}
		if got := must("ip", "-json", "-N", "route", "show", "exact", podRoute.String()); got != cni {
			t.Fatal("CNI route changed during reselection")
		}
		must("ip", "route", "del", podRoute.String(), "dev", "pod0", "proto", "99")
		if err := r.Set(&router.Config{LocalAddrs: local, Routes: []netip.Prefix{def, podRoute}}); err != nil {
			t.Fatal(err)
		}
		must("ip", "route", "del", podRoute.String(), "dev", "deepai0", "proto", "186")
		if err := r.Set(&router.Config{LocalAddrs: local, Routes: []netip.Prefix{def}}); err != nil {
			t.Fatal("missing route prevented map update:", err)
		}
		if err := r.clearEgress(); err != nil {
			t.Fatal(err)
		}
		if b, err := run("ip", probe...); err == nil {
			t.Fatalf("source %s leaked to main routing after stop: %s", source, b)
		}
		if err := r.setEgress(true); err != nil {
			t.Fatal(err)
		}
		if result := must("ip", probe...); !strings.Contains(result, `"dev":"deepai0"`) {
			t.Fatalf("source %s failed to resume: %s", source, result)
		}
		if err := r.removeEgress(); err != nil {
			t.Fatal(err)
		}
		if err := r.removeEgress(); err != nil {
			t.Fatalf("disable not idempotent: %v", err)
		}
		if result := must("ip", probe...); !strings.Contains(result, `"dev":"eth0"`) {
			t.Fatalf("explicit disable failed to restore normal route: %s", result)
		}
		if after := must("ip", "-json", "-N", "rule", "show"); after != beforeRules {
			t.Fatalf("source %s left policy rules: %s", source, after)
		}
		var routes []struct{ Table any }
		if err := json.Unmarshal([]byte(must("ip", "-json", "-N", "route", "show", "table", "all")), &routes); err != nil {
			t.Fatal(err)
		}
		for _, route := range routes {
			if fmt.Sprint(route.Table) == "186" {
				t.Fatal("disable left route table186 entries")
			}
		}
		if after := must("ip", "-json", "-N", "route", "show", "table", "main"); after != beforeMain {
			t.Fatal("main routes changed")
		}
		if after := normalizeAcceptanceSnapshot(must("iptables-save", "-t", "nat")); after != beforeNAT {
			t.Fatalf("NAT cleanup altered unrelated rules or left owned state: %s", after)
		}
		t.Logf("%s: install, stop fail-closed, resume, disable, repeated cleanup and unrelated-state preservation passed", source)
	}
}
