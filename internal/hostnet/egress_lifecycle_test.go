package hostnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestEgressDisableConsumesRealNumericIPRouteJSON(t *testing.T) {
	for _, routeTypes := range [][2]any{{"1", "7"}, {1, 7}, {"unicast", "unreachable"}, {nil, "7"}} {
		t.Run(fmt.Sprint(routeTypes), func(t *testing.T) {
			routes := []map[string]any{
				{"dst": "default", "dev": "deepai0", "type": routeTypes[0], "table": "186", "protocol": "186", "metric": 100},
				{"dst": "default", "type": routeTypes[1], "table": "186", "protocol": "186", "metric": 32760},
				{"dst": "default", "type": "7", "table": "187", "protocol": "186", "metric": 32760},
			}
			data, _ := json.Marshal(routes)
			var deleted []string
			run := func(name string, args ...string) ([]byte, error) {
				if slices.Contains(args, "-json") {
					return data, nil
				}
				deleted = append(deleted, name+" "+strings.Join(args, " "))
				return nil, nil
			}
			if err := removeEgressRoutes(run, "deepai0", true); err != nil {
				t.Fatal(err)
			}
			if len(deleted) != 2 || !slices.Contains(deleted, "ip route del unreachable default table 186 metric 32760 proto 186") || !slices.Contains(deleted, "ip route del default dev deepai0 table 186 metric 100 proto 186") {
				t.Fatalf("numeric route cleanup failed or touched unrelated table: %v", deleted)
			}
		})
	}
}

func TestEgressDisableParsesSplitAndCompactRulePrefixes(t *testing.T) {
	for _, rules := range []string{
		`[{"priority":20186,"src":"10.42.1.0","srclen":24,"dst":"100.96.0.0","dstlen":16,"table":"254","protocol":"186"},{"priority":21186,"src":"10.42.1.0","srclen":24,"table":"186","protocol":"186"}]`,
		`[{"priority":20186,"src":"10.42.1.0/24","dst":"100.96.0.0/16","table":254,"protocol":186},{"priority":21186,"src":"10.42.1.0/24","table":186,"protocol":186}]`,
	} {
		var deleted []string
		r := &hostRouter{iface: "deepai0", egressAddress: netip.MustParseAddr("100.96.0.2"), egressSources: []netip.Prefix{netip.MustParsePrefix("10.42.1.0/24")}, protected: []netip.Prefix{netip.MustParsePrefix("100.96.0.0/16")}}
		r.run = func(name string, args ...string) ([]byte, error) {
			if slices.Contains(args, "-json") && slices.Contains(args, "rule") {
				return []byte(rules), nil
			}
			if slices.Contains(args, "-json") {
				return []byte(`[{"type":"7","dst":"default","table":"186","protocol":"186","metric":32760}]`), nil
			}
			if slices.Contains(args, "del") {
				deleted = append(deleted, name+" "+strings.Join(args, " "))
			}
			return nil, nil
		}
		if err := r.removeEgress(); err != nil {
			t.Fatal(err)
		}
		want := []string{"ip rule del from 10.42.1.0/24 to 100.96.0.0/16 lookup main priority 20186 protocol 186", "ip rule del from 10.42.1.0/24 lookup 186 priority 21186 protocol 186", "ip route del unreachable default table 186 metric 32760 proto 186"}
		if !slices.Equal(deleted, want) {
			t.Fatalf("pod source policy survived disable: %v", deleted)
		}
	}
}

type natModel struct{ chains map[string][][]string }

func TestNATSetupResumesAfterEachInterruptedMutation(t *testing.T) {
	for _, mode := range []string{"gateway", "pod", "egress"} {
		setup := func(run commandRunner) error {
			sources := []netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}
			r := &hostRouter{run: run, iface: "deepai0", hostCIDR: netip.MustParsePrefix("100.64.0.0/10"),
				egressAddress: netip.MustParseAddr("100.64.0.2"), egressSources: sources,
				protected: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}
			switch mode {
			case "gateway":
				return configureGateway(run, "eth0", sources)
			case "pod":
				return r.setPodSourcePreservation(sources)
			default:
				return r.setEgressSNAT()
			}
		}
		newModel := func() *natModel {
			return &natModel{chains: map[string][][]string{
				"POSTROUTING": {{"-j", "UNRELATED"}}, "UNRELATED": {{"-j", "MASQUERADE"}},
			}}
		}
		complete := newModel()
		var mutations []string
		err := setup(func(name string, args ...string) ([]byte, error) {
			if name == "iptables" && (slices.Contains(args, "-N") || slices.Contains(args, "-I") || slices.Contains(args, "-A")) {
				mutations = append(mutations, strings.Join(args, " "))
			}
			return complete.run(name, args...)
		})
		if err != nil {
			t.Fatal(err)
		}
		want, _ := complete.run("iptables", "-w", "-t", "nat", "-S")
		for _, failed := range mutations {
			t.Run(mode+"/"+failed, func(t *testing.T) {
				model := newModel()
				interrupted := errors.New("interrupted firewall mutation")
				err := setup(func(name string, args ...string) ([]byte, error) {
					if name == "iptables" && strings.Join(args, " ") == failed {
						return nil, interrupted
					}
					return model.run(name, args...)
				})
				if !errors.Is(err, interrupted) {
					t.Fatalf("installation hid its failure: %v", err)
				}
				for range 2 {
					if err := setup(model.run); err != nil {
						t.Fatal(err)
					}
				}
				got, _ := model.run("iptables", "-w", "-t", "nat", "-S")
				if string(got) != string(want) {
					t.Fatalf("retry changed rule order, duplicated entries or lost unrelated rules:\n%s\nwant:\n%s", got, want)
				}
			})
		}
	}
}

func (m *natModel) run(name string, args ...string) ([]byte, error) {
	if name != "iptables" {
		return []byte("[]"), nil
	}
	if len(args) < 4 || !slices.Equal(args[:3], []string{"-w", "-t", "nat"}) {
		return nil, fmt.Errorf("unexpected command %v", args)
	}
	args = args[3:]
	if args[0] == "-n" {
		args = args[1:]
	}
	if args[0] == "-S" {
		var out []string
		for chain, rules := range m.chains {
			if chain != "POSTROUTING" {
				out = append(out, "-N "+chain)
			}
			for _, rule := range rules {
				out = append(out, "-A "+chain+" "+strings.Join(rule, " "))
			}
		}
		sort.Strings(out)
		return []byte(strings.Join(out, "\n")), nil
	}
	op, chain := args[0], args[1]
	rules, exists := m.chains[chain]
	if op == "-N" {
		if exists {
			return nil, errors.New("exists")
		}
		m.chains[chain] = nil
		return nil, nil
	}
	if !exists {
		return nil, errors.New("absent chain")
	}
	rule := slices.Clone(args[2:])
	index := slices.IndexFunc(rules, func(r []string) bool { return slices.Equal(r, rule) })
	switch op {
	case "-L":
	case "-C":
		if index < 0 {
			return nil, errors.New("absent")
		}
	case "-I":
		m.chains[chain] = append([][]string{rule}, rules...)
	case "-A":
		m.chains[chain] = append(rules, rule)
	case "-D":
		if index < 0 {
			return nil, errors.New("absent")
		}
		m.chains[chain] = slices.Delete(rules, index, index+1)
	case "-X":
		if len(rules) > 0 {
			return nil, errors.New("not empty")
		}
		delete(m.chains, chain)
	default:
		return nil, fmt.Errorf("unexpected operation %s", op)
	}
	return nil, nil
}

func (m *natModel) verdict(chain string, p forwardedPacket, dnat bool) string {
	for _, rule := range m.chains[chain] {
		match, target, negate := true, "", false
		for i := 0; i < len(rule); i++ {
			if rule[i] == "!" {
				negate = true
				continue
			}
			key, value := rule[i], rule[i+1]
			i++
			switch key {
			case "-s":
				match = match && netip.MustParsePrefix(value).Contains(p.src)
			case "-d":
				match = match && netip.MustParsePrefix(value).Contains(p.dst)
			case "-o":
				match = match && value == p.out
			case "--ctstate":
				match = match && (dnat != negate)
				negate = false
			case "-j":
				target = value
			case "-m", "--to-source":
			default:
				panic(key)
			}
		}
		if !match {
			continue
		}
		switch target {
		case "RETURN", "ACCEPT", "SNAT", "MASQUERADE":
			return target
		}
		if next := m.verdict(target, p, dnat); next != "RETURN" {
			return next
		}
	}
	return "RETURN"
}

func TestPrivatePodSourcePreservedBeforeFlannelWithAndWithoutEgress(t *testing.T) {
	m := &natModel{chains: map[string][][]string{"POSTROUTING": {{"-j", "FLANNEL-POSTRTG"}}, "FLANNEL-POSTRTG": {{"-s", "10.42.0.0/16", "-j", "MASQUERADE"}}}}
	r := &hostRouter{run: m.run, iface: "deepai0", hostCIDR: netip.MustParsePrefix("100.64.0.0/10"), egressAddress: netip.MustParseAddr("100.64.0.2"), egressSources: []netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}, protected: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}}
	if err := r.setPodSourcePreservation([]netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}); err != nil {
		t.Fatal(err)
	}
	p := forwardedPacket{src: netip.MustParseAddr("10.42.2.5"), dst: netip.MustParseAddr("100.64.0.1"), out: "deepai0"}
	for _, egress := range []bool{false, true} {
		if egress {
			if err := r.setEgressSNAT(); err != nil {
				t.Fatal(err)
			}
		}
		if got := m.verdict("POSTROUTING", p, false); got != "ACCEPT" {
			t.Fatalf("egress=%v: private pod source was rewritten: %s", egress, got)
		}
		if got := m.verdict("POSTROUTING", p, true); got != "MASQUERADE" {
			t.Fatalf("Service DNAT/SNAT was bypassed: %s", got)
		}
		other := p
		other.src = netip.MustParseAddr("10.42.3.5")
		if got := m.verdict("POSTROUTING", other, false); got != "MASQUERADE" {
			t.Fatalf("unassigned pod prefix bypassed CNI: %s", got)
		}
	}
	p.dst = netip.MustParseAddr("93.184.216.34")
	if got := m.verdict("POSTROUTING", p, false); got != "SNAT" {
		t.Fatalf("Internet source must use authenticated overlay identity: %s", got)
	}
}

func TestEgressShutdownAndCrashRecoveryRetainUnreachableGuard(t *testing.T) {
	var commands []string
	active := true
	r := &hostRouter{iface: "deepai0", egressReady: true, egressAddress: netip.MustParseAddr("100.64.0.2"), egressSources: []netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}}
	r.run = func(name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if strings.Contains(command, "-json -N route") {
			if active {
				return []byte(`[{"dst":"default","table":186,"protocol":186,"metric":100,"dev":"deepai0"},{"dst":"default","type":"unreachable","table":186,"protocol":186,"metric":32760}]`), nil
			}
			return []byte(`[{"dst":"default","type":"unreachable","table":186,"protocol":186,"metric":32760}]`), nil
		}
		if strings.Contains(command, "route del default") {
			active = false
		}
		return []byte("[]"), nil
	}
	if err := r.clearEgress(); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("shutdown retained usable default")
	}
	for _, cmd := range commands {
		if strings.Contains(cmd, "rule del") || strings.Contains(cmd, "route del unreachable") {
			t.Fatalf("shutdown permits physical fallback: %s", cmd)
		}
	}
	// A new process cannot rely on in-memory bookkeeping to know
	// whether an earlier process left a usable default in the kernel.
	active = true
	r.egressReady = false
	if err := r.setEgress(false); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("offline recovery retained stale default without a selected gateway")
	}
}

func TestGatewayCleanupIsExactAndIdempotent(t *testing.T) {
	m := &natModel{chains: map[string][][]string{"POSTROUTING": {{"-j", "DEEPAI-EGRESS"}, {"-j", "UNRELATED"}}, "DEEPAI-EGRESS": {{"-s", "100.64.0.0/10", "-o", "eth0", "-j", "MASQUERADE"}, {"-s", "192.0.2.0/24", "-o", "eth1", "-j", "MASQUERADE"}}, "UNRELATED": {{"-s", "198.51.100.0/24", "-j", "MASQUERADE"}}}}
	rules := [][]string{{"POSTROUTING", "-j", "DEEPAI-EGRESS"}, {"DEEPAI-EGRESS", "-s", "100.64.0.0/10", "-o", "eth0", "-j", "MASQUERADE"}}
	for range 2 {
		if err := removeNATRules(m.run, "DEEPAI-EGRESS", rules); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.chains["DEEPAI-EGRESS"]) != 1 || m.chains["DEEPAI-EGRESS"][0][1] != "192.0.2.0/24" || len(m.chains["POSTROUTING"]) != 2 || len(m.chains["UNRELATED"]) != 1 {
		t.Fatal("cleanup removed another source, hook, or chain")
	}
}
