package hostnet

import (
	"net/netip"
	"slices"
)

func (r *hostRouter) podSourceRules(prefixes []netip.Prefix) [][]string {
	rules := [][]string{{"POSTROUTING", "-j", "DEEPAI-POD-SRC"}}
	for _, prefix := range prefixes {
		// A RETURN would continue into Flannel's general pod masquerade rule.
		// ACCEPT ends nat traversal only for direct private-host traffic. Keep
		// kube-proxy's Service DNAT/SNAT semantics, even for host-network backends.
		rules = append(rules, []string{"DEEPAI-POD-SRC", "-s", prefix.String(), "-d", r.hostCIDR.String(), "-o", r.iface, "-m", "conntrack", "!", "--ctstate", "DNAT", "-j", "ACCEPT"})
	}
	return rules
}

func (r *hostRouter) setPodSourcePreservation(prefixes []netip.Prefix) error {
	if slices.Equal(prefixes, r.podRoutes) {
		return nil
	}
	if len(r.podRoutes) > 0 {
		if err := removeNATRules(r.run, "DEEPAI-POD-SRC", r.podSourceRules(r.podRoutes)); err != nil {
			return err
		}
	}
	if len(prefixes) == 0 {
		r.podRoutes = nil
		return nil
	}
	if _, err := r.run("iptables", "-w", "-t", "nat", "-n", "-L", "DEEPAI-POD-SRC"); err != nil {
		if _, err = r.run("iptables", "-w", "-t", "nat", "-N", "DEEPAI-POD-SRC"); err != nil {
			return err
		}
	}
	for _, rule := range r.podSourceRules(prefixes) {
		if _, err := r.run("iptables", append([]string{"-w", "-t", "nat", "-C"}, rule...)...); err != nil {
			op := "-A"
			if rule[0] == "POSTROUTING" {
				op = "-I"
			}
			if _, err = r.run("iptables", append([]string{"-w", "-t", "nat", op}, rule...)...); err != nil {
				return err
			}
		}
	}
	r.podRoutes = slices.Clone(prefixes)
	return nil
}
