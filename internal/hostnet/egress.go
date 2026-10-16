package hostnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
)

// Egress never changes the main table's default. The terminal unreachable route
// prevents opted-in sources silently leaking via the physical interface when
// the coordinator removes an unhealthy gateway and has no replacement.
func (r *hostRouter) egressRules() [][]string {
	var rules [][]string
	for _, source := range r.egressSources {
		for _, dst := range r.protected {
			rules = append(rules, []string{"from", source.String(), "to", dst.String(), "lookup", "main", "priority", "20186", "protocol", "186"})
		}
		rules = append(rules, []string{"from", source.String(), "lookup", "186", "priority", "21186", "protocol", "186"})
	}
	return rules
}

func (r *hostRouter) setEgress(active bool) error {
	if !r.egressReady {
		// Refuse to claim a table or priority already used by another product.
		b, err := r.run("ip", "-json", "-N", "route", "show", "table", "all")
		if err != nil {
			return err
		}
		var tableRoutes []struct {
			Table    any `json:"table"`
			Protocol any `json:"protocol"`
		}
		if err = json.Unmarshal(b, &tableRoutes); err != nil {
			return err
		}
		for _, route := range tableRoutes {
			if fmt.Sprint(route.Table) == "186" && fmt.Sprint(route.Protocol) != "186" {
				return errors.New("egress table 186 is owned by another service")
			}
		}
		b, err = r.run("ip", "-json", "-N", "rule", "show")
		if err != nil {
			return err
		}
		var rules []struct {
			Priority int `json:"priority"`
			Protocol any `json:"protocol"`
		}
		if err = json.Unmarshal(b, &rules); err != nil {
			return err
		}
		for _, rule := range rules {
			if (rule.Priority == 20186 || rule.Priority == 21186) && fmt.Sprint(rule.Protocol) != "186" {
				return errors.New("egress rule priority is owned by another service")
			}
		}
		if err := r.setEgressSNAT(); err != nil {
			return err
		}
		// A named table is local to Connect; tagged route/rule operations only
		// replace Connect's exact entries and leave the rest of the host alone.
		if _, err := r.run("ip", "route", "replace", "unreachable", "default", "table", "186", "metric", "32760", "proto", "186"); err != nil {
			return err
		}
		for _, rule := range r.egressRules() {
			_, _ = r.run("ip", append([]string{"rule", "del"}, rule...)...)
			if _, err := r.run("ip", append([]string{"rule", "add"}, rule...)...); err != nil {
				return err
			}
		}
		r.egressReady = true
	}
	if active {
		if _, err := r.run("ip", "route", "replace", "default", "dev", r.iface, "table", "186", "metric", "100", "proto", "186"); err != nil {
			return err
		}
	} else {
		// Reconcile stale owned state after a crash as well as live withdrawal.
		if err := removeEgressRoutes(r.run, r.iface, false); err != nil {
			return err
		}
	}
	r.egressActive = active
	return nil
}

func (r *hostRouter) clearEgress() error {
	if !r.egressReady {
		return nil
	}
	// Containers can survive K3s/agent shutdown. Retain the source rules and
	// terminal unreachable route until the operator explicitly disables egress.
	// Otherwise a restart window silently leaks opted-in traffic to the uplink.
	result := removeEgressRoutes(r.run, r.iface, false)
	result = errors.Join(result, removeNATRules(r.run, "DEEPAI-EXIT-SRC", r.egressSNATRules()))
	r.egressReady, r.egressActive = false, false
	return result
}

func (r *hostRouter) egressSNATRules() [][]string {
	rules := [][]string{{"POSTROUTING", "-j", "DEEPAI-EXIT-SRC"}}
	for _, dst := range r.protected {
		rules = append(rules, []string{"DEEPAI-EXIT-SRC", "-d", dst.String(), "-j", "RETURN"})
	}
	for _, source := range r.egressSources {
		if source.IsSingleIP() && source.Addr() == r.egressAddress {
			continue
		}
		rules = append(rules, []string{"DEEPAI-EXIT-SRC", "-s", source.String(), "-o", r.iface, "-j", "SNAT", "--to-source", r.egressAddress.String()})
	}
	return rules
}

func (r *hostRouter) setEgressSNAT() error {
	if !r.egressAddress.Is4() {
		return errors.New("egress requires the host's IPv4 overlay address")
	}
	if _, err := r.run("iptables", "-w", "-t", "nat", "-n", "-L", "DEEPAI-EXIT-SRC"); err != nil {
		if _, err = r.run("iptables", "-w", "-t", "nat", "-N", "DEEPAI-EXIT-SRC"); err != nil {
			return err
		}
	}
	for _, rule := range r.egressSNATRules() {
		if _, err := r.run("iptables", append([]string{"-w", "-t", "nat", "-C"}, rule...)...); err != nil {
			action := "-A"
			// Run before flannel's general pod masquerade rule so WireGuard sees
			// this node's authenticated overlay source, never its physical IP.
			if rule[0] == "POSTROUTING" || rule[len(rule)-1] == "RETURN" {
				action = "-I"
			}
			if _, err = r.run("iptables", append([]string{"-w", "-t", "nat", action}, rule...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// ConfigureGateway enables explicitly requested Internet SNAT on a hub. The
// sources must be the cluster's approved host/pod ranges; it never masquerades
// arbitrary host traffic or flushes another service's firewall rules.
func ConfigureGateway(ctx context.Context, iface string, sources []netip.Prefix) error {
	if iface == "" || len(iface) > 15 {
		return errors.New("invalid gateway egress interface")
	}
	for _, c := range iface {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return errors.New("invalid gateway egress interface")
		}
	}
	if len(sources) == 0 {
		return errors.New("gateway requires explicit source prefixes")
	}
	for _, p := range sources {
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() == 0 || p != p.Masked() {
			return errors.New("invalid gateway source prefix")
		}
	}
	run := func(name string, args ...string) ([]byte, error) {
		b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return b, fmt.Errorf("gateway %s: %w: %s", name, err, b)
		}
		return b, nil
	}
	return configureGateway(run, iface, sources)
}

func configureGateway(run commandRunner, iface string, sources []netip.Prefix) error {
	if _, err := run("ip", "link", "show", "dev", iface); err != nil {
		return err
	}
	if _, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	if _, err := run("iptables", "-w", "-t", "nat", "-n", "-L", "DEEPAI-EGRESS"); err != nil {
		if _, err = run("iptables", "-w", "-t", "nat", "-N", "DEEPAI-EGRESS"); err != nil {
			return err
		}
	}
	rules := [][]string{{"POSTROUTING", "-j", "DEEPAI-EGRESS"}}
	for _, source := range slices.Compact(slices.Clone(sources)) {
		rules = append(rules, []string{"DEEPAI-EGRESS", "-s", source.String(), "-o", iface, "-j", "MASQUERADE"})
	}
	for _, rule := range rules {
		if _, err := run("iptables", append([]string{"-w", "-t", "nat", "-C"}, rule...)...); err != nil {
			if _, err = run("iptables", append([]string{"-w", "-t", "nat", "-A"}, rule...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// RemoveGateway removes only the exact source/interface rules installed for
// this gateway. Shared or unrelated chain contents are left intact.
func RemoveGateway(ctx context.Context, iface string, sources []netip.Prefix) error {
	rules := [][]string{{"POSTROUTING", "-j", "DEEPAI-EGRESS"}}
	for _, source := range sources {
		rules = append(rules, []string{"DEEPAI-EGRESS", "-s", source.String(), "-o", iface, "-j", "MASQUERADE"})
	}
	return removeNATRules(egressCommandRunner(ctx), "DEEPAI-EGRESS", rules)
}

// RemoveEgress is the explicit opt-out operation. Normal engine shutdown keeps
// the source policy and unreachable fallback so surviving workloads fail closed.
// Call this only after the disabled configuration has been durably recorded.
func RemoveEgress(ctx context.Context, iface string, address netip.Addr, sources, protected []netip.Prefix) error {
	r := &hostRouter{run: egressCommandRunner(ctx), iface: iface, egressAddress: address, egressSources: sources, protected: protected}
	return r.removeEgress()
}

// PrepareEgress records the source guard before a newly configured engine
// starts. There is deliberately no usable default route until a map selects a
// gateway; this also protects a new source while replacing an older source.
func PrepareEgress(ctx context.Context, iface string, address netip.Addr, sources, protected []netip.Prefix) error {
	r := &hostRouter{run: egressCommandRunner(ctx), iface: iface, egressAddress: address, egressSources: sources, protected: protected}
	return r.setEgress(false)
}

func egressCommandRunner(ctx context.Context) commandRunner {
	return func(name string, args ...string) ([]byte, error) {
		b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return b, fmt.Errorf("egress %s: %w: %s", name, err, b)
		}
		return b, nil
	}
}

func (r *hostRouter) removeEgress() error {
	if err := removeNATRules(r.run, "DEEPAI-EXIT-SRC", r.egressSNATRules()); err != nil {
		return err
	}
	b, err := r.run("ip", "-json", "-N", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Src, Dst        string
		SrcLen          *int `json:"srclen"`
		DstLen          *int `json:"dstlen"`
		Table, Protocol any
		Priority        int
	}
	if err = json.Unmarshal(b, &rules); err != nil {
		return err
	}
	otherConsumer := false
	for _, rule := range rules {
		owned := fmt.Sprint(rule.Protocol) == "186"
		source := rulePrefix(rule.Src, rule.SrcLen)
		ours := owned && slices.Contains(r.egressSources, source)
		destination := rulePrefix(rule.Dst, rule.DstLen)
		defaultDestination := rule.Dst == "" || rule.Dst == "all" || (destination.IsValid() && destination.Bits() == 0)
		ownConsumer := ours && rule.Priority == 21186 && fmt.Sprint(rule.Table) == "186" && defaultDestination
		if fmt.Sprint(rule.Table) == "186" && !ownConsumer {
			otherConsumer = true
		}
		if ownConsumer {
			if _, err = r.run("ip", "rule", "del", "from", source.String(), "lookup", "186", "priority", "21186", "protocol", "186"); err != nil {
				return err
			}
		} else if ours && rule.Priority == 20186 && (fmt.Sprint(rule.Table) == "254" || fmt.Sprint(rule.Table) == "main") {
			dst := rulePrefix(rule.Dst, rule.DstLen)
			if !dst.IsValid() || !slices.Contains(r.protected, dst) {
				continue
			}
			if _, err = r.run("ip", "rule", "del", "from", source.String(), "to", dst.String(), "lookup", "main", "priority", "20186", "protocol", "186"); err != nil {
				return err
			}
		}
	}
	if otherConsumer {
		return nil
	}
	return removeEgressRoutes(r.run, r.iface, true)
}

// iproute2 versions encode rule selectors either as CIDRs or as an address
// plus srclen/dstlen. Missing lengths on a bare address mean a host selector.
func rulePrefix(address string, length *int) netip.Prefix {
	if p, err := netip.ParsePrefix(address); err == nil {
		if length != nil && *length != p.Bits() {
			return netip.Prefix{}
		}
		if p == p.Masked() {
			return p
		}
		return netip.Prefix{}
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}
	}
	bits := ip.BitLen()
	if length != nil {
		bits = *length
	}
	p := netip.PrefixFrom(ip, bits)
	if !p.IsValid() || p != p.Masked() {
		return netip.Prefix{}
	}
	return p
}

func removeEgressRoutes(run commandRunner, iface string, fallback bool) error {
	b, err := run("ip", "-json", "-N", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var routes []struct {
		Dst, Dev              string
		Type, Table, Protocol any
		Metric                int
	}
	if err = json.Unmarshal(b, &routes); err != nil {
		return err
	}
	for _, route := range routes {
		if fmt.Sprint(route.Table) != "186" || fmt.Sprint(route.Protocol) != "186" || (route.Dst != "default" && route.Dst != "0.0.0.0/0") {
			continue
		}
		var args []string
		kind := fmt.Sprint(route.Type)
		if route.Dev == iface && route.Metric == 100 && (kind == "<nil>" || kind == "" || kind == "unicast" || kind == "1") {
			args = []string{"route", "del", "default", "dev", iface, "table", "186", "metric", "100", "proto", "186"}
		} else if fallback && (kind == "unreachable" || kind == "7") && route.Metric == 32760 {
			args = []string{"route", "del", "unreachable", "default", "table", "186", "metric", "32760", "proto", "186"}
		}
		if args != nil {
			if _, err = run("ip", args...); err != nil {
				return err
			}
		}
	}
	return nil
}

// Inspect before deleting so cleanup is idempotent without treating arbitrary
// command errors as "already absent". Match complete rules, never a broad flush.
func removeNATRules(run commandRunner, chain string, rules [][]string) error {
	b, err := run("iptables", "-w", "-t", "nat", "-S")
	if err != nil {
		return err
	}
	var existing [][]string
	chainExists, hasOtherRules := false, false
	for line := range strings.SplitSeq(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "-N" && fields[1] == chain {
			chainExists = true
		}
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		existing = append(existing, fields[1:])
		if fields[1] == chain && !slices.ContainsFunc(rules, func(rule []string) bool { return slices.Equal(rule, fields[1:]) }) {
			hasOtherRules = true
		}
	}
	for _, rule := range existing {
		if !slices.ContainsFunc(rules, func(want []string) bool { return slices.Equal(want, rule) }) || (rule[0] != chain && hasOtherRules) {
			continue
		}
		if hasOtherRules && rule[len(rule)-1] == "RETURN" {
			continue // protected destinations may also serve another source
		}
		if _, err = run("iptables", append([]string{"-w", "-t", "nat", "-D"}, rule...)...); err != nil {
			return err
		}
	}
	if chainExists && !hasOtherRules {
		for _, rule := range existing {
			if slices.ContainsFunc(rules, func(want []string) bool { return slices.Equal(want, rule) }) {
				continue
			}
			for i, value := range rule {
				if (value == "-j" || value == "-g") && i+1 < len(rule) && rule[i+1] == chain {
					return nil // an unrelated caller still references the empty chain
				}
			}
		}
		_, err = run("iptables", "-w", "-t", "nat", "-X", chain)
	}
	return err
}
