package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestTransportRecoveryRequiresTimeoutThenAuthenticatedMap(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int32
	}{
		{"HTTP unavailable", errors.New("coordinator /machine/map: HTTP 502"), 0},
		{"authentication rejected", errors.New("coordinator /machine/map: HTTP 403"), 0},
		{"offline error", errors.New("coordinator unavailable"), 0},
		{"request canceled", context.Canceled, 0},
		{"transport deadline", fmt.Errorf("Noise map: %w", context.DeadlineExceeded), 1},
		{"socket timeout", &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, id := testState(t, 1)
			e := &testEngine{closed: make(chan struct{})}
			a := &agent{dir: t.TempDir(), identity: id, state: s, engine: e}
			valid := func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
				return &tailcfg.MapResponse{Node: s.Self.Clone(), DERPMap: s.DERPMap, PacketFilter: s.PacketFilter}, nil
			}
			a.options.Fetch = valid
			if err := a.refresh(context.Background()); err != nil || e.rebinds.Load() != 0 {
				t.Fatal("initial synchronization rebound cached transport", err)
			}
			trusted := a.state.UpdatedAt
			a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
				return nil, tc.err
			}
			for range 3 {
				if err := a.refresh(context.Background()); err == nil || e.rebinds.Load() != 0 {
					t.Fatal("offline coordinator reset the data plane", err)
				}
			}
			if !a.state.UpdatedAt.Equal(trusted) {
				t.Fatal("failed control requests renewed cached trust")
			}
			a.options.Fetch = valid
			for range 3 {
				if err := a.refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if e.rebinds.Load() != tc.want || !e.healthy.Load() {
				t.Fatalf("rebind count=%d, want %d; healthy=%v", e.rebinds.Load(), tc.want, e.healthy.Load())
			}
			if a.state.Self.Key != id.Node.Public() || a.state.Self.Machine != id.Machine.Public() {
				t.Fatal("transport recovery replaced identity")
			}
		})
	}
}

func TestTransportRecoveryWaitsForValidMap(t *testing.T) {
	for _, mode := range []string{"invalid map", "HTTP error", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			s, id := testState(t, 1)
			e := &testEngine{closed: make(chan struct{})}
			a := &agent{dir: t.TempDir(), identity: id, state: s, engine: e}
			a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
				return nil, context.DeadlineExceeded
			}
			_ = a.refresh(context.Background())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
				if mode == "HTTP error" {
					return nil, errors.New("HTTP 502")
				}
				if mode == "shutdown" {
					cancel()
					return nil, context.DeadlineExceeded
				}
				return &tailcfg.MapResponse{}, nil
			}
			if err := a.refresh(ctx); err == nil || e.rebinds.Load() != 0 {
				t.Fatal("uncommitted map triggered recovery", err)
			}
			a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
				return &tailcfg.MapResponse{Node: s.Self.Clone(), DERPMap: s.DERPMap, PacketFilter: s.PacketFilter}, nil
			}
			if err := a.refresh(context.Background()); err != nil || e.rebinds.Load() != 1 {
				t.Fatal("successful map did not consume the earlier transport timeout once", err)
			}
		})
	}
}

func TestTransportRecoverySerializesTimerAndManualRefresh(t *testing.T) {
	s, id := testState(t, 1)
	e := &testEngine{closed: make(chan struct{})}
	a := &agent{dir: t.TempDir(), identity: id, state: s, engine: e}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	calls := 0 // Access serialized by refreshMu; the race detector checks this.
	a.options.Fetch = func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error) {
		calls++
		entered <- struct{}{}
		if calls == 1 {
			<-release
			return nil, context.DeadlineExceeded
		}
		return &tailcfg.MapResponse{Node: s.Self.Clone(), DERPMap: s.DERPMap, PacketFilter: s.PacketFilter}, nil
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- a.refresh(context.Background()) }()
	<-entered
	go func() { second <- a.refresh(context.Background()) }()
	select {
	case <-entered:
		t.Fatal("manual and timer control requests overlapped")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := <-second; err != nil || !e.healthy.Load() || e.rebinds.Load() != 1 {
		t.Fatalf("ordered recovery: err=%v healthy=%v rebinds=%d", err, e.healthy.Load(), e.rebinds.Load())
	}
}
