package hostnet

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// firewallModel implements the small iptables subset used by hostRouter and
// evaluates the resulting chains. These tests check packet verdicts, including
// policy denies, instead of relying only on which iptables commands were run.
type firewallModel struct {
	chains map[string][][]string
}

func newFirewallModel() *firewallModel {
	return &firewallModel{chains: map[string][][]string{"INPUT": {}, "FORWARD": {}}}
}

func (f *firewallModel) run(name string, args ...string) ([]byte, error) {
	if name != "iptables" {
		return nil, nil
	}
	if len(args) < 3 || args[0] != "-w" {
		return nil, fmt.Errorf("unsupported iptables command: %q", args)
	}
	args = args[1:]
	if args[0] == "-n" {
		args = args[1:]
	}
	op, chain := args[0], args[1]
	rules, exists := f.chains[chain]
	if op == "-N" {
		if exists {
			return nil, errors.New("chain exists")
		}
		f.chains[chain] = nil
		return nil, nil
	}
	if !exists {
		return nil, errors.New("chain does not exist")
	}
	rule := slices.Clone(args[2:])
	index := slices.IndexFunc(rules, func(r []string) bool { return slices.Equal(r, rule) })
	switch op {
	case "-L":
	case "-S":
		var lines []string
		for _, r := range rules {
			lines = append(lines, "-A "+chain+" "+strings.Join(r, " "))
		}
		return []byte(strings.Join(lines, "\n")), nil
	case "-I":
		f.chains[chain] = append([][]string{rule}, rules...)
	case "-A":
		f.chains[chain] = append(rules, rule)
	case "-C", "-D":
		if index < 0 {
			return nil, errors.New("rule does not exist")
		}
		if op == "-D" {
			f.chains[chain] = slices.Delete(rules, index, index+1)
		}
	case "-X":
		if len(rules) != 0 {
			return nil, errors.New("chain is not empty")
		}
		delete(f.chains, chain)
	default:
		return nil, fmt.Errorf("unsupported operation %s", op)
	}
	return nil, nil
}

type forwardedPacket struct {
	in, out  string
	src, dst netip.Addr
}

func (f *firewallModel) verdict(chain string, p forwardedPacket) string {
	for _, rule := range f.chains[chain] {
		match, target := true, ""
		for i := 0; i < len(rule); i += 2 {
			switch rule[i] {
			case "-i":
				match = match && rule[i+1] == p.in
			case "-o":
				match = match && rule[i+1] == p.out
			case "-s":
				match = match && netip.MustParsePrefix(rule[i+1]).Contains(p.src)
			case "-d":
				match = match && netip.MustParsePrefix(rule[i+1]).Contains(p.dst)
			case "-j":
				target = rule[i+1]
			default:
				panic("unsupported evaluator match: " + rule[i])
			}
		}
		if !match {
			continue
		}
		switch target {
		case "ACCEPT", "DROP", "REJECT", "RETURN":
			return target
		default:
			if v := f.verdict(target, p); v != "RETURN" {
				return v
			}
		}
	}
	if chain == "FORWARD" {
		return "DROP" // Connect must still work with a restrictive base policy.
	}
	return "RETURN"
}

func (f *firewallModel) installNetworkPolicy() {
	// K3s's kube-router inserts its hook at position 1 both at startup and
	// during policy reconciliation. Deny pod egress to this private host.
	f.chains["KUBE-ROUTER-FORWARD"] = [][]string{
		{"-s", "10.42.2.0/24", "-d", "100.64.0.1/32", "-j", "REJECT"},
		{"-s", "100.64.0.1/32", "-d", "10.42.2.0/24", "-j", "REJECT"},
	}
	f.chains["FORWARD"] = append([][]string{{"-j", "KUBE-ROUTER-FORWARD"}}, f.chains["FORWARD"]...)
}

func assertNetworkPolicyVerdicts(t *testing.T, f *firewallModel) {
	t.Helper()
	for _, p := range []forwardedPacket{
		{in: "cni0", out: "deepai0", src: netip.MustParseAddr("10.42.2.5"), dst: netip.MustParseAddr("100.64.0.1")},
		{in: "deepai0", out: "cni0", src: netip.MustParseAddr("100.64.0.1"), dst: netip.MustParseAddr("10.42.2.5")},
	} {
		if got := f.verdict("FORWARD", p); got != "REJECT" {
			t.Fatalf("NetworkPolicy deny bypassed for %+v: %s", p, got)
		}
	}
	allowed := forwardedPacket{in: "cni0", out: "deepai0", src: netip.MustParseAddr("10.42.3.5"), dst: netip.MustParseAddr("100.64.0.1")}
	if got := f.verdict("FORWARD", allowed); got != "ACCEPT" {
		t.Fatalf("permitted overlay packet blocked: %s", got)
	}
	unrelated := forwardedPacket{in: "eth1", out: "eth0", src: netip.MustParseAddr("192.0.2.1"), dst: netip.MustParseAddr("198.51.100.1")}
	if got := f.verdict("FORWARD", unrelated); got != "DROP" {
		t.Fatalf("unrelated forwarding enabled: %s", got)
	}
}

func TestForwardingRespectsNetworkPolicyAcrossStartupOrderAndRestart(t *testing.T) {
	for _, cniFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("cni_first_%t", cniFirst), func(t *testing.T) {
			f := newFirewallModel()
			if cniFirst {
				f.installNetworkPolicy()
			}
			r := &hostRouter{iface: "deepai0", run: f.run}
			if err := r.Up(); err != nil {
				t.Fatal(err)
			}
			if !cniFirst {
				f.installNetworkPolicy()
			}
			assertNetworkPolicyVerdicts(t, f)
			// A crash can leave all Connect chains in place. A new agent must
			// retain the effective deny when adopting those existing rules.
			restarted := &hostRouter{iface: "deepai0", run: f.run}
			if err := restarted.Up(); err != nil {
				t.Fatal(err)
			}
			assertNetworkPolicyVerdicts(t, f)
		})
	}
}

func TestForwardingReordersDuplicateOwnedHooksWithoutBypassingPolicy(t *testing.T) {
	f := newFirewallModel()
	f.installNetworkPolicy()
	f.chains["DEEPAI-FWD"] = [][]string{{"-i", "deepai0", "-j", "ACCEPT"}, {"-o", "deepai0", "-j", "ACCEPT"}}
	ownedHook := []string{"-j", "DEEPAI-FWD"}
	f.chains["FORWARD"] = append([][]string{slices.Clone(ownedHook)}, f.chains["FORWARD"]...)
	f.chains["FORWARD"] = append(f.chains["FORWARD"], slices.Clone(ownedHook))
	denied := forwardedPacket{in: "cni0", out: "deepai0", src: netip.MustParseAddr("10.42.2.5"), dst: netip.MustParseAddr("100.64.0.1")}
	if f.verdict("FORWARD", denied) != "ACCEPT" {
		t.Fatal("misplaced hook fixture does not reproduce policy bypass")
	}
	r := &hostRouter{iface: "deepai0", run: f.run}
	if err := r.Up(); err != nil {
		t.Fatal(err)
	}
	assertNetworkPolicyVerdicts(t, f)
	if len(f.chains["FORWARD"]) != 2 || !slices.Equal(f.chains["FORWARD"][0], []string{"-j", "KUBE-ROUTER-FORWARD"}) {
		t.Fatalf("reconciliation damaged policy or retained duplicate hooks: %v", f.chains["FORWARD"])
	}
}

func TestForwardingRespectsExplicitHostFirewallDeny(t *testing.T) {
	f := newFirewallModel()
	f.chains["FORWARD"] = [][]string{{"-j", "DROP"}}
	r := &hostRouter{iface: "deepai0", run: f.run}
	if err := r.Up(); err != nil {
		t.Fatal(err)
	}
	p := forwardedPacket{in: "deepai0", out: "eth0", src: netip.MustParseAddr("100.64.0.2"), dst: netip.MustParseAddr("192.0.2.1")}
	if got := f.verdict("FORWARD", p); got != "DROP" {
		t.Fatalf("explicit host deny bypassed: %s", got)
	}
}
