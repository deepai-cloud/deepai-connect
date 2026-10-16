package hostnet

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/wgengine/router"
)

func TestEgressPolicyPreservesControlPlaneAndFailsClosed(t *testing.T) {
	var commands []string
	active := false
	r := &hostRouter{iface: "deepai0", egressSources: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, protected: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}, run: func(name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		if slices.Contains(args, "replace") && slices.Contains(args, "100") {
			active = true
		}
		if active && slices.Contains(args, "-json") && slices.Contains(args, "route") {
			return []byte(`[{"dst":"default","table":186,"protocol":186,"metric":100,"dev":"deepai0"}]`), nil
		}
		return []byte("[]"), nil
	}}
	c := &router.Config{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	if err := r.Set(c); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "ip route replace default dev deepai0 table 186 metric 100 proto 186") {
		t.Fatal("missing isolated egress route")
	}
	if !slices.Contains(commands, "ip rule add from 10.42.0.0/16 to 100.64.0.0/10 lookup main priority 20186 protocol 186") {
		t.Fatal("control-plane destination not excluded")
	}
	if !slices.Contains(commands, "ip route replace unreachable default table 186 metric 32760 proto 186") {
		t.Fatal("gateway loss would leak to physical default")
	}
	c.Routes = nil
	if err := r.Set(c); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "ip route del default dev deepai0 table 186 metric 100 proto 186") {
		t.Fatal("unhealthy gateway remains installed")
	}
	for _, command := range commands {
		if strings.Contains(command, "route replace default") && !strings.Contains(command, "table 186") {
			t.Fatal("system default route changed")
		}
	}
}

func TestGatewaySNATIsScoped(t *testing.T) {
	var commands []string
	run := func(name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if slices.Contains(args, "-C") {
			return nil, errors.New("absent")
		}
		return nil, nil
	}
	if err := configureGateway(run, "eth0", []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	want := "iptables -w -t nat -A DEEPAI-EGRESS -s 10.42.0.0/16 -o eth0 -j MASQUERADE"
	if !slices.Contains(commands, want) {
		t.Fatalf("missing source-scoped NAT: %v", commands)
	}
	for _, command := range commands {
		if strings.Contains(command, " -F ") || strings.Contains(command, " flush ") {
			t.Fatal("flushed other firewall rules")
		}
	}
}

func TestExistingCNIPodRouteIsRetained(t *testing.T) {
	var mutated bool
	r := &hostRouter{iface: "deepai0", cniRanges: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, run: func(name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-json" {
			return []byte(`[{"dev":"flannel.1","protocol":"boot"}]`), nil
		}
		mutated = true
		return nil, nil
	}}
	if err := r.Set(&router.Config{Routes: []netip.Prefix{netip.MustParsePrefix("10.42.5.0/24")}}); err != nil {
		t.Fatal(err)
	}
	if mutated || len(r.routes) > 0 {
		t.Fatal("claimed or mutated a CNI-owned route")
	}
}

func TestPodEgressUsesAuthenticatedHostSourceBeforeCNIMasquerade(t *testing.T) {
	var commands []string
	r := &hostRouter{iface: "deepai0", egressAddress: netip.MustParseAddr("100.64.0.2"), egressSources: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, run: func(name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		if slices.Contains(args, "-C") {
			return nil, errors.New("absent")
		}
		return nil, nil
	}}
	if err := r.setEgressSNAT(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "iptables -w -t nat -I POSTROUTING -j DEEPAI-EXIT-SRC") {
		t.Fatal("source translation must run before CNI masquerade")
	}
	if !slices.Contains(commands, "iptables -w -t nat -A DEEPAI-EXIT-SRC -s 10.42.0.0/16 -o deepai0 -j SNAT --to-source 100.64.0.2") {
		t.Fatal("worker pod traffic is not translated into its authorized WireGuard identity")
	}
}

func TestEgressRestoresOwnRulesWithNamedProtocolDatabase(t *testing.T) {
	r := &hostRouter{iface: "deepai0", egressAddress: netip.MustParseAddr("100.64.0.2"), egressSources: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, run: func(_ string, args ...string) ([]byte, error) {
		if slices.Contains(args, "-json") {
			protocol := "bgp"
			if slices.Contains(args, "-N") {
				protocol = "186"
			}
			if slices.Contains(args, "rule") {
				return []byte(`[{"priority":21186,"protocol":"` + protocol + `"}]`), nil
			}
			return []byte(`[{"table":186,"protocol":"` + protocol + `"}]`), nil
		}
		return nil, nil
	}}
	if err := r.setEgress(true); err != nil {
		t.Fatalf("existing owned egress state was rejected after restart: %v", err)
	}
	if !r.egressReady || !r.egressActive {
		t.Fatal("saved egress configuration was not restored")
	}
}
