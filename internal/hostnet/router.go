package hostnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/wgengine/router"
)

type commandRunner func(string, ...string) ([]byte, error)

func commandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, err, b)
	}
	return b, nil
}

// hostRouter owns only routes tagged protocol 186 on its TUN and explicit
// DEEPAI chains. In particular it never flushes a table/chain, changes the
// default route, or replaces a route owned by a CNI or another VPN.
type hostRouter struct {
	iface         string
	port          uint16
	run           commandRunner
	addrs         []netip.Prefix
	routes        []netip.Prefix
	up            bool
	egressSources []netip.Prefix
	protected     []netip.Prefix
	cniRanges     []netip.Prefix
	egressReady   bool
	egressAddress netip.Addr
	hostCIDR      netip.Prefix
	podRoutes     []netip.Prefix
}

func (r *hostRouter) Up() error {
	if _, err := r.run("ip", "link", "set", "dev", r.iface, "up"); err != nil {
		return err
	}
	if r.port == 0 {
		r.port = DefaultPort
	}
	if err := r.installTransportBoundary(); err != nil {
		return err
	}
	for _, chain := range []string{"DEEPAI-IN", "DEEPAI-FWD"} {
		if _, err := r.run("iptables", "-w", "-n", "-L", chain); err != nil {
			if _, err = r.run("iptables", "-w", "-N", chain); err != nil {
				return err
			}
		}
	}
	for _, rule := range r.rules() {
		if rule[0] == "FORWARD" {
			continue
		}
		if _, err := r.run("iptables", append([]string{"-w", "-C"}, rule...)...); err != nil {
			if _, err = r.run("iptables", append([]string{"-w", "-I"}, rule...)...); err != nil {
				return err
			}
		}
	}
	if err := r.appendForwardHook(); err != nil {
		return err
	}
	r.up = true
	return nil
}

// Forwarded overlay packets must pass existing host firewall and Kubernetes
// NetworkPolicy rules before our scoped ACCEPT rules. K3s's kube-router installs
// its FORWARD hook at position 1, including when it starts after the overlay.
// Move misplaced Connect hooks to the end and remove duplicates while
// preserving every other rule and its order. Never insert this hook at the top.
func (r *hostRouter) appendForwardHook() error {
	b, err := r.run("iptables", "-w", "-S", "FORWARD")
	if err != nil {
		return err
	}
	want := []string{"-A", "FORWARD", "-j", "DEEPAI-FWD"}
	count, lastIsOurs := 0, false
	for line := range strings.SplitSeq(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != "FORWARD" {
			continue
		}
		lastIsOurs = slices.Equal(fields, want)
		if lastIsOurs {
			count++
		}
	}
	if count == 1 && lastIsOurs {
		return nil
	}
	for range count {
		if _, err = r.run("iptables", "-w", "-D", "FORWARD", "-j", "DEEPAI-FWD"); err != nil {
			return err
		}
	}
	_, err = r.run("iptables", "-w", "-A", "FORWARD", "-j", "DEEPAI-FWD")
	return err
}

func (r *hostRouter) rules() [][]string {
	return [][]string{
		{"DEEPAI-IN", "-i", r.iface, "-j", "ACCEPT"},
		{"DEEPAI-IN", "-p", "udp", "--dport", strconv.Itoa(int(r.port)), "-j", "ACCEPT"},
		{"DEEPAI-FWD", "-i", r.iface, "-j", "ACCEPT"},
		{"DEEPAI-FWD", "-o", r.iface, "-j", "ACCEPT"},
		{"INPUT", "-j", "DEEPAI-IN"},
		{"FORWARD", "-j", "DEEPAI-FWD"},
	}
}

func (r *hostRouter) Set(c *router.Config) error {
	if c == nil {
		c = new(router.Config)
	}
	var routes []netip.Prefix
	defaultActive := false
	for _, p := range c.Routes {
		if !p.IsValid() {
			return errors.New("invalid overlay route")
		}
		if p.Bits() == 0 {
			if !p.Addr().Is4() || len(r.egressSources) == 0 {
				return errors.New("default route requires an explicit IPv4 egress source policy")
			}
			defaultActive = true
		} else {
			routes = append(routes, p)
		}
	}
	if len(c.LocalAddrs) > 0 && len(r.egressSources) > 0 {
		r.egressAddress = c.LocalAddrs[0].Addr()
		if err := r.setEgress(defaultActive); err != nil {
			return err
		}
	}
	for _, p := range c.LocalAddrs {
		if !slices.Contains(r.addrs, p) {
			if _, err := r.run("ip", "address", "replace", p.String(), "dev", r.iface); err != nil {
				return err
			}
			r.addrs = append(r.addrs, p)
		}
	}
	for _, p := range routes {
		if slices.Contains(r.routes, p) {
			continue
		}
		// A non-Connect route at this exact prefix is never overwritten. It
		// commonly belongs to flannel and marks the locally hosted pod CIDR.
		// Numeric mode is essential: iproute2's default protocol database names
		// 186 "bgp", and local rt_protos files can rename arbitrary numbers.
		b, err := r.run("ip", "-json", "-N", "route", "show", "exact", p.String())
		if err != nil {
			return err
		}
		var existing []struct {
			Dev      string `json:"dev"`
			Protocol any    `json:"protocol"`
		}
		if err = json.Unmarshal(b, &existing); err != nil {
			return err
		}
		owned, cniOwned := false, false
		for _, route := range existing {
			if route.Dev != r.iface || fmt.Sprint(route.Protocol) != "186" {
				for _, clusterRange := range r.cniRanges {
					if clusterRange.Contains(p.Addr()) && p.Bits() >= clusterRange.Bits() {
						cniOwned = true
					}
				}
				if cniOwned {
					continue
				}
				return fmt.Errorf("refusing to replace existing route to %s on %s", p, route.Dev)
			}
			owned = true
		}
		if cniOwned {
			continue
		}
		if !owned {
			if _, err = r.run("ip", "route", "add", p.String(), "dev", r.iface, "proto", "186"); err != nil {
				return err
			}
		}
		r.routes = append(r.routes, p)
	}
	for _, p := range slices.Clone(r.routes) {
		if !slices.Contains(routes, p) {
			if err := r.removeOwnedRoute(p); err != nil {
				return err
			}
			r.routes = slices.DeleteFunc(r.routes, func(a netip.Prefix) bool { return a == p })
		}
	}
	for _, p := range slices.Clone(r.addrs) {
		if !slices.Contains(c.LocalAddrs, p) {
			if _, err := r.run("ip", "address", "del", p.String(), "dev", r.iface); err != nil {
				return err
			}
			r.addrs = slices.DeleteFunc(r.addrs, func(a netip.Prefix) bool { return a == p })
		}
	}
	if len(c.SubnetRoutes) > len(c.LocalAddrs) {
		if _, err := r.run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return err
		}
	}
	return nil
}

func (r *hostRouter) ownsRoute(prefix netip.Prefix) (bool, error) {
	b, err := r.run("ip", "-json", "-N", "route", "show", "exact", prefix.String())
	if err != nil {
		return false, err
	}
	var current []struct {
		Dev      string
		Protocol any
	}
	if err = json.Unmarshal(b, &current); err != nil {
		return false, err
	}
	for _, route := range current {
		if route.Dev == r.iface && fmt.Sprint(route.Protocol) == "186" {
			return true, nil
		}
	}
	return false, nil
}

// CNI reconciliation can replace a route after Connect installed it. Cached
// bookkeeping is not proof of current kernel ownership, including on shutdown.
func (r *hostRouter) removeOwnedRoute(prefix netip.Prefix) error {
	owned, err := r.ownsRoute(prefix)
	if err != nil || !owned {
		return err
	}
	if _, err = r.run("ip", "route", "del", prefix.String(), "dev", r.iface, "proto", "186"); err == nil {
		return nil
	}
	// A CNI may win the race between inspection and deletion. Suppress only a
	// proven disappearance; permission errors and failures of existing routes
	// still propagate rather than silently claiming a map was applied.
	owned, checkErr := r.ownsRoute(prefix)
	if checkErr == nil && !owned {
		return nil
	}
	return errors.Join(err, checkErr)
}

func (r *hostRouter) Close() error {
	if !r.up {
		return nil
	}
	err := r.Set(nil)
	err = errors.Join(err, r.clearEgress())
	err = errors.Join(err, r.removeTransportBoundary())
	if len(r.podRoutes) > 0 {
		err = errors.Join(err, removeNATRules(r.run, "DEEPAI-POD-SRC", r.podSourceRules(r.podRoutes)))
	}
	rules := r.rules()
	for i := len(rules) - 1; i >= 0; i-- {
		_, e := r.run("iptables", append([]string{"-w", "-D"}, rules[i]...)...)
		err = errors.Join(err, e)
	}
	for _, chain := range []string{"DEEPAI-IN", "DEEPAI-FWD"} {
		_, e := r.run("iptables", "-w", "-X", chain)
		err = errors.Join(err, e)
	}
	r.up = false
	return err
}
