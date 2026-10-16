package unified

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/netip"
	"path/filepath"
	"slices"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

func configureEgress(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "private installation directory")
	disable := fs.Bool("disable", false, "disable this optional Internet gateway or source policy")
	var iface, source string
	if command == "gateway" {
		fs.StringVar(&iface, "interface", "", "physical Internet egress interface")
	} else {
		fs.StringVar(&source, "source", "", "local pod prefix or local overlay host /32")
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if *disable && (iface != "" || source != "") {
		return errors.New("--disable cannot be combined with --interface or --source")
	}
	if err := hostRequired(); err != nil {
		return err
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	*dir = absolute
	unlock, err := platform.Lock(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	i, err := loadInstallation(*dir)
	if err != nil {
		return err
	}
	if i.PendingEgressCleanup != nil {
		if err := restartEgressConfiguration(ctx, *dir, i); err != nil {
			return err
		}
	}
	s, err := hostnet.LoadState(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	oldInterface, oldSources := i.GatewayInterface, slices.Clone(i.EgressSources)
	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	if command == "egress" {
		if i.GatewayInterface != "" {
			return errors.New("an Internet gateway already uses its local egress interface")
		}
		if *disable {
			i.EgressSources = nil
		} else {
			p, e := netip.ParsePrefix(source)
			if e != nil || p != p.Masked() {
				return errors.New("egress source must be a canonical CIDR")
			}
			local := slices.Contains(s.Self.Addresses, p) || slices.ContainsFunc(i.PodRoutes, func(local netip.Prefix) bool { return local.Contains(p.Addr()) && p.Bits() >= local.Bits() })
			if !local {
				return errors.New("egress source must be this host's overlay address or an assigned local pod prefix")
			}
			i.EgressSources = []netip.Prefix{p}
		}
	} else {
		if len(i.EgressSources) > 0 {
			return errors.New("an egress consumer cannot also offer an Internet gateway")
		}
		if i.Config.Role != "hub" {
			return errors.New("only a hub can offer an Internet gateway")
		}
		if !*disable && (iface == hostnet.DefaultInterface || iface == "lo") {
			return errors.New("gateway interface must be a physical Internet interface")
		}
		if !*disable {
			if _, e := net.InterfaceByName(iface); e != nil {
				return e
			}
		}
		m, e := cluster.New(i.Config, nil)
		if e != nil {
			return e
		}
		k, e := localKube(ctx, m)
		if e != nil {
			return e
		}
		srv, e := coordinator.New(ctx, coordinator.Config{Store: k.store})
		if e != nil {
			return e
		}
		defer srv.Close()
		err = srv.Update(ctx, func(state *coordinator.State) error {
			n := state.Nodes[s.Self.Machine.String()]
			if n == nil || n.Revoked {
				return errors.New("gateway has no active membership")
			}
			if *disable {
				n.ApprovedRoutes = slices.DeleteFunc(n.ApprovedRoutes, func(p netip.Prefix) bool { return p == defaultRoute })
				return nil // preserve shared/custom policy needed by other gateways
			}
			if !slices.Contains(n.ApprovedRoutes, defaultRoute) {
				n.ApprovedRoutes = append(n.ApprovedRoutes, defaultRoute)
			}
			return addGatewayInternetPolicy(state, i.Config.HostCIDR, i.Config.PodCIDR, i.Config.ServiceCIDR)
		})
		if err != nil {
			return err
		}
		i.GatewayInterface = iface
		if *disable {
			i.GatewayInterface = ""
		}
	}
	if err = s.WithEgressConfig(i.EgressSources, i.GatewayInterface != "").Validate(nil, s.UpdatedAt); err != nil {
		return err
	}
	// Save both the desired state and its cleanup intent before stopping anything.
	// A crash is completed by resume or agent startup; no credentials are changed.
	i.PendingEgressCleanup = &egressCleanup{GatewayInterface: oldInterface, Sources: oldSources, Address: s.Self.Addresses[0].Addr(), Interface: s.Interface}
	if err = saveInstallation(*dir, i); err != nil {
		return err
	}
	if len(i.EgressSources) > 0 {
		// Install the newly opted-in source guard before systemd stops units:
		// K3s containers may continue forwarding throughout that operation.
		if err = hostnet.PrepareEgress(ctx, s.Interface, s.Self.Addresses[0].Addr(), i.EgressSources, []netip.Prefix{s.HostCIDR, s.PodCIDR, s.ServiceCIDR}); err != nil {
			return err
		}
	}
	if err = restartEgressConfiguration(ctx, *dir, i); err != nil {
		return err
	}
	return resume(ctx, *dir, i)
}

type egressCleanup struct {
	GatewayInterface string         `json:"gatewayInterface,omitempty"`
	Sources          []netip.Prefix `json:"sources,omitempty"`
	Address          netip.Addr     `json:"address"`
	Interface        string         `json:"interface"`
}

func restartEgressConfiguration(ctx context.Context, dir string, i *installation) error {
	r := cluster.ExecRunner{}
	if _, err := r.Run(ctx, nil, "systemctl", "stop", cluster.UnitName, cluster.AgentUnitName); err != nil {
		return err
	}
	return finishEgressCleanup(ctx, dir, i)
}

func finishEgressCleanup(ctx context.Context, dir string, i *installation) error {
	return finishEgressCleanupWith(ctx, dir, i, egressCleanupActions{prepare: hostnet.PrepareEgress, removeSources: hostnet.RemoveEgress, removeGateway: hostnet.RemoveGateway})
}

type egressCleanupActions struct {
	prepare, removeSources func(context.Context, string, netip.Addr, []netip.Prefix, []netip.Prefix) error
	removeGateway          func(context.Context, string, []netip.Prefix) error
}

func finishEgressCleanupWith(ctx context.Context, dir string, i *installation, actions egressCleanupActions) error {
	pending := i.PendingEgressCleanup
	if pending == nil {
		return nil
	}
	snapshot, err := hostnet.LoadState(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	snapshot = snapshot.WithEgressConfig(i.EgressSources, i.GatewayInterface != "")
	if err = hostnet.SaveState(i.Config.AgentStateDir, snapshot); err != nil {
		return err
	}
	protected := []netip.Prefix{snapshot.HostCIDR, snapshot.PodCIDR, snapshot.ServiceCIDR}
	if len(i.EgressSources) > 0 {
		if err = actions.prepare(ctx, snapshot.Interface, snapshot.Self.Addresses[0].Addr(), i.EgressSources, protected); err != nil {
			return err
		}
	}
	removedSources := slices.DeleteFunc(slices.Clone(pending.Sources), func(p netip.Prefix) bool { return slices.Contains(i.EgressSources, p) })
	if len(removedSources) > 0 {
		if err = actions.removeSources(ctx, pending.Interface, pending.Address, removedSources, protected); err != nil {
			return err
		}
	}
	if pending.GatewayInterface != "" {
		if err = actions.removeGateway(ctx, pending.GatewayInterface, []netip.Prefix{snapshot.HostCIDR, snapshot.PodCIDR}); err != nil {
			return err
		}
	}
	i.PendingEgressCleanup = nil
	return saveInstallation(dir, i)
}
