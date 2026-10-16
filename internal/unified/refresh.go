package unified

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/tailcfg"
)

type refreshMapFunc func(context.Context, string, *hostnet.Identity) (*tailcfg.MapResponse, error)

func refreshCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "private installation directory")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := hostRequired(); err != nil {
		return err
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if err = refreshSavedNetwork(ctx, absolute, authenticatedRefreshMap); err != nil {
		return err
	}
	fmt.Printf("Authenticated network state refreshed. Run deepai-connect resume --dir %s.\n", absolute)
	return nil
}

func authenticatedRefreshMap(ctx context.Context, origin string, id *hostnet.Identity) (*tailcfg.MapResponse, error) {
	client := coordinator.Client{ServerURL: origin, MachineKey: id.Machine}
	return client.Map(ctx, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: id.Node.Public(), DiscoKey: id.Disco.Public(), ReadOnly: true})
}

// Refresh is deliberately separate from offline startup: only a current,
// authenticated coordinator response can authorize replacing expired trust.
// Neither saved private keys nor peer/route claims are registered or changed.
func refreshSavedNetwork(ctx context.Context, dir string, fetch refreshMapFunc) error {
	unlock, err := platform.Lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	i, err := loadInstallation(dir)
	if err != nil {
		return err
	}
	unlockAgent, err := platform.Lock(filepath.Join(i.Config.AgentStateDir, "agent-lock"))
	if err != nil {
		return fmt.Errorf("refresh requires the host agent stopped: %w", err)
	}
	defer unlockAgent()
	identity, err := platform.ReadFile(filepath.Join(i.Config.AgentStateDir, "identity.json"))
	if err != nil {
		return fmt.Errorf("refresh requires the existing private identity: %w", err)
	}
	var id hostnet.Identity
	if err = json.Unmarshal(identity, &id); err != nil || id.Machine.IsZero() || id.Node.IsZero() || id.Disco.IsZero() {
		return errors.New("invalid saved private identity")
	}
	raw, err := platform.ReadFile(filepath.Join(i.Config.AgentStateDir, "overlay.json"))
	if err != nil {
		return err
	}
	var saved hostnet.State
	if err = json.Unmarshal(raw, &saved); err != nil {
		return errors.New("invalid saved network state")
	}
	now := time.Now()
	if err = validateRefreshSnapshot(&saved, &id, i, now); err != nil {
		return err
	}
	request, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	m, err := fetch(request, saved.CoordinatorURL, &id)
	if err != nil {
		return fmt.Errorf("authenticated coordinator refresh failed; saved cache unchanged: %w", err)
	}
	now = time.Now()
	if m == nil || m.KeepAlive || m.Node == nil || m.DERPMap == nil || m.Peers == nil || m.PacketFilter == nil || m.ControlTime == nil || now.Sub(*m.ControlTime) > 5*time.Minute || m.ControlTime.Sub(now) > 5*time.Minute {
		return errors.New("refresh requires a current complete coordinator map")
	}
	if !m.Node.MachineAuthorized || m.Node.Expired || m.Node.Key != id.Node.Public() || m.Node.Machine != id.Machine.Public() || m.Node.DiscoKey != id.Disco.Public() || m.Node.ID != saved.Self.ID || m.Node.StableID != saved.Self.StableID || !slices.Equal(m.Node.Addresses, saved.Self.Addresses) {
		return errors.New("coordinator refresh changed or revoked the saved host identity")
	}
	for _, peer := range m.Peers {
		if peer == nil || !peer.MachineAuthorized || peer.Expired {
			return errors.New("coordinator refresh contains an unauthorized peer")
		}
	}
	// Local route opt-ins constrain a new map; old peer state never contributes
	// endpoints, routes, policy or DERP authority to this recovery operation.
	base := saved.WithEgressConfig(i.EgressSources, i.GatewayInterface != "")
	base.PodRoutes = slices.Clone(i.PodRoutes)
	base.Peers, base.PacketFilter, base.DERPMap = nil, nil, nil
	base.DirectHubEndpoints = nil
	fresh, err := base.WithMap(m, now)
	if err != nil {
		return fmt.Errorf("invalid authenticated network map: %w", err)
	}
	if slices.Contains(fresh.Self.Tags, "tag:hub") && len(m.Node.Endpoints) > 0 {
		fresh.DirectHubEndpoints[fresh.Self.Key] = slices.Clone(m.Node.Endpoints)
	}
	if err = fresh.Validate(&id, now); err != nil {
		return err
	}
	// SaveState validates again and atomically replaces the cache. Every error
	// above leaves the original bytes, timestamps and private keys untouched.
	return hostnet.SaveState(i.Config.AgentStateDir, fresh)
}

func validateRefreshSnapshot(saved *hostnet.State, id *hostnet.Identity, i *installation, now time.Time) error {
	if saved.UpdatedAt.IsZero() || saved.ExpiresAt.IsZero() || !saved.ExpiresAt.After(saved.UpdatedAt) || saved.ExpiresAt.Sub(saved.UpdatedAt) > hostnet.CacheLifetime || saved.UpdatedAt.After(now.Add(5*time.Minute)) {
		return errors.New("saved network state has invalid trust bounds")
	}
	if err := enrollment.ValidateURL(saved.CoordinatorURL); err != nil {
		return err
	}
	origin := i.Services.PublicURL
	if i.Invitation != nil {
		origin = i.Invitation.URL
	}
	address, err := netip.ParseAddr(i.Config.OverlayIP)
	if err != nil || !address.Is4() {
		return errors.New("installed overlay address is invalid")
	}
	if saved.CoordinatorURL != origin || saved.ClusterID != i.ClusterID || saved.HostCIDR.String() != i.Config.HostCIDR || saved.PodCIDR.String() != i.Config.PodCIDR || saved.ServiceCIDR.String() != i.Config.ServiceCIDR || saved.Self == nil || !slices.Equal(saved.Self.Addresses, []netip.Prefix{netip.PrefixFrom(address, 32)}) {
		return errors.New("saved network state differs from the installed cluster identity")
	}
	for _, route := range saved.ApprovedRoutes {
		if !route.IsValid() || !route.Addr().Is4() || route != route.Masked() {
			return errors.New("saved local route opt-in is invalid")
		}
	}
	// This clone is used only for structural checks and never leaves this
	// function. Relax time fields without activating or persisting old authority.
	check := saved.Clone()
	check.UpdatedAt, check.ExpiresAt = now, now.Add(hostnet.CacheLifetime)
	for _, node := range append([]*tailcfg.Node{check.Self}, check.Peers...) {
		if node != nil {
			node.KeyExpiry = time.Time{}
		}
	}
	if err := check.Validate(id, now); err != nil {
		return fmt.Errorf("invalid saved network structure: %w", err)
	}
	return nil
}
