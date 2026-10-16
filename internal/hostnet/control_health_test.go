package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/health"
	"tailscale.com/tailcfg"
	"tailscale.com/util/eventbus"
)

func TestAuthenticatedMapControlsDERPHealth(t *testing.T) {
	s, id := testState(t, 1)
	e := &testEngine{closed: make(chan struct{})}
	a := &agent{dir: t.TempDir(), identity: id, state: s, engine: e}
	response := func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
		return &tailcfg.MapResponse{Node: s.Self.Clone(), DERPMap: s.DERPMap, PacketFilter: s.PacketFilter}, nil
	}
	if e.healthy.Load() {
		t.Fatal("cached state claimed current control connectivity")
	}
	a.options.Fetch = response
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.healthy.Load() {
		t.Fatal("authenticated applied map did not enable DERP home changes")
	}
	trusted := a.state.UpdatedAt
	a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
		return nil, errors.New("authentication rejected")
	}
	if err := a.refresh(context.Background()); err == nil || e.healthy.Load() {
		t.Fatal("failed authentication retained control health")
	}
	if !a.state.UpdatedAt.Equal(trusted) {
		t.Fatal("failed authentication renewed cached trust")
	}
	a.options.Fetch = response
	if err := a.refresh(context.Background()); err != nil || !e.healthy.Load() {
		t.Fatal("successful reconnect did not restore control health", err)
	}
	a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
		return &tailcfg.MapResponse{}, nil
	}
	if err := a.refresh(context.Background()); err == nil || e.healthy.Load() {
		t.Fatal("invalid map enabled control health")
	}
	a.options.Fetch = response
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	trusted = a.state.UpdatedAt
	_ = a.refresh(ctx)
	if e.healthy.Load() {
		t.Fatal("canceled poll enabled control health")
	}
	if !a.state.UpdatedAt.Equal(trusted) {
		t.Fatal("canceled poll renewed cached trust")
	}
}

func TestControlHealthReachesUpstreamDERPGate(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	tr := &transport{health: health.NewTracker(bus)}
	if tr.health.GetInPollNetMap() {
		t.Fatal("new transport starts online")
	}
	tr.SetControlHealthy(true)
	if !tr.health.GetInPollNetMap() {
		t.Fatal("upstream magicsock cannot observe authenticated control health")
	}
	tr.SetControlHealthy(false)
	if tr.health.GetInPollNetMap() {
		t.Fatal("offline transport left upstream DERP home changes enabled")
	}
}
