package hostnet

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// ConfigureVXLANBoundary restricts the local K3s/Flannel listener to decrypted
// overlay ingress. Linux's IPv4 VXLAN lower-device setting does not bind its
// receive socket to that interface. Apply this before starting K3s, and retain
// it when the agent stops because container/CNI processes can survive shutdown.
func ConfigureVXLANBoundary(ctx context.Context, iface string) error {
	if iface == "" || len(iface) > 15 {
		return errors.New("invalid VXLAN overlay interface")
	}
	for _, c := range iface {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return errors.New("invalid VXLAN overlay interface")
		}
	}
	return configureVXLANBoundary(egressCommandRunner(ctx), iface)
}

func configureVXLANBoundary(run commandRunner, iface string) error {
	for _, boundary := range []struct {
		table, chain, hook string
		match              []string
	}{
		{"raw", "DEEPAI-VXLAN", "PREROUTING", []string{"-p", "udp", "-m", "udp", "--dport", "8472", "-m", "addrtype", "--dst-type", "LOCAL"}},
		{"mangle", "DEEPAI-VXLAN-IN", "INPUT", []string{"-p", "udp", "-m", "udp", "--dport", "8472"}},
	} {
		if _, err := run("iptables", "-w", "-t", boundary.table, "-n", "-L", boundary.chain); err != nil {
			if _, err = run("iptables", "-w", "-t", boundary.table, "-N", boundary.chain); err != nil {
				return err
			}
		}
		if err := firstExactFirewallRule(run, boundary.table, boundary.chain, []string{"!", "-i", iface, "-j", "DROP"}); err != nil {
			return err
		}
		if err := firstExactFirewallRule(run, boundary.table, boundary.hook, append(boundary.match, "-j", boundary.chain)); err != nil {
			return err
		}
	}
	// LOCAL limits this protection to the listener on this machine. It does
	// not block unrelated VXLAN datagrams merely forwarded by the host. INPUT
	// in mangle additionally covers local broadcast/multicast delivery, whose route type
	// isn't LOCAL, before filter ACCEPTs even if K3s prepends new filter rules.
	return nil
}

func firstExactFirewallRule(run commandRunner, table, chain string, rule []string) error {
	b, err := run("iptables", "-w", "-t", table, "-S", chain)
	if err != nil {
		return err
	}
	// An exact temporary copy keeps the boundary closed while canonical copies
	// are reconciled. Delete by full rule specification, never by a position
	// that another firewall writer could shift between commands.
	temporary := append(slices.Clone(rule[:len(rule)-2]), "-m", "comment", "--comment", "deepai-connect-vxlan-reconcile")
	temporary = append(temporary, rule[len(rule)-2:]...)
	count, temporaryCount, position := 0, 0, 0
	firstIsOurs := false
	for line := range strings.SplitSeq(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != chain {
			continue
		}
		// iptables may quote the comment in -S output even without spaces.
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] == "--comment" {
				fields[i+1] = strings.TrimSuffix(strings.TrimPrefix(fields[i+1], `"`), `"`)
			}
		}
		position++
		if slices.Equal(fields[2:], rule) {
			count++
			firstIsOurs = firstIsOurs || position == 1
		}
		if slices.Equal(fields[2:], temporary) {
			temporaryCount++
		}
	}
	if count == 1 && firstIsOurs && temporaryCount == 0 {
		return nil
	}
	// Establish the boundary first: Flannel can remain running while the agent
	// restarts. Removing old copies first would briefly reopen its listener.
	if _, err = run("iptables", append([]string{"-w", "-t", table, "-I", chain}, temporary...)...); err != nil {
		return err
	}
	for range count {
		if _, err = run("iptables", append([]string{"-w", "-t", table, "-D", chain}, rule...)...); err != nil {
			return err
		}
	}
	if _, err = run("iptables", append([]string{"-w", "-t", table, "-I", chain}, rule...)...); err != nil {
		return err
	}
	for range temporaryCount + 1 {
		if _, err = run("iptables", append([]string{"-w", "-t", table, "-D", chain}, temporary...)...); err != nil {
			return err
		}
	}
	return nil
}
