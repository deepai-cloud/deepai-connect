package hostnet

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

type testEngine struct {
	applied atomic.Int32
	healthy atomic.Bool
	rebinds atomic.Int32
	closed  chan struct{}
}

func (e *testEngine) Apply(s *State, c bool) error           { e.applied.Add(1); return nil }
func (e *testEngine) Endpoints() []netip.AddrPort            { return nil }
func (e *testEngine) NetInfo() *tailcfg.NetInfo              { return &tailcfg.NetInfo{PreferredDERP: 7} }
func (e *testEngine) SetControlHealthy(v bool)               { e.healthy.Store(v) }
func (e *testEngine) Rebind()                                { e.rebinds.Add(1) }
func (e *testEngine) Ping(context.Context, netip.Addr) error { return nil }
func (e *testEngine) Done() <-chan struct{}                  { return e.closed }
func (e *testEngine) Close() {
	select {
	case <-e.closed:
	default:
		close(e.closed)
	}
}

func TestAgentNeverRecreatesMissingDeviceIdentity(t *testing.T) {
	dir := t.TempDir()
	s, _ := testState(t, 1)
	if err := SaveState(dir, s); err != nil {
		t.Fatal(err)
	}
	started := false
	err := Run(context.Background(), dir, Options{EngineFactory: func(*State, *Identity, logger.Logf) (Engine, error) {
		started = true
		return nil, errors.New("unexpected engine creation")
	}})
	if err == nil || started {
		t.Fatalf("missing identity started transport: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); !os.IsNotExist(err) {
		t.Fatal("agent wrote a replacement device identity")
	}
}

func TestAgentRestoresBeforeCoordinatorAndAppliesSameEngine(t *testing.T) {
	dir, err := os.MkdirTemp("", "hostnet-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s, id := testState(t, 1)
	b, _ := json.Marshal(id)
	if err := platform.WriteFile(filepath.Join(dir, "identity.json"), b, true); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, s); err != nil {
		t.Fatal(err)
	}
	var started atomic.Bool
	observedNetInfo := make(chan int, 1)
	e := &testEngine{closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, dir, Options{
			PollInterval: 10 * time.Millisecond,
			EngineFactory: func(state *State, identity *Identity, logf logger.Logf) (Engine, error) {
				if state.Self.Key != id.Node.Public() {
					return nil, errors.New("wrong restored identity")
				}
				started.Store(true)
				return e, nil
			},
			Fetch: func(ctx context.Context, id *Identity, s *State, eps []netip.AddrPort) (*tailcfg.MapResponse, error) {
				if !started.Load() {
					return nil, errors.New("coordinator was contacted before restoring transport")
				}
				if s.Self.Hostinfo.Valid() && s.Self.Hostinfo.AsStruct().NetInfo != nil {
					select {
					case observedNetInfo <- s.Self.Hostinfo.AsStruct().NetInfo.PreferredDERP:
					default:
					}
				}
				return nil, errors.New("coordinator unavailable")
			},
		})
	}()
	ready, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := WaitReady(ready, dir); err != nil {
		t.Fatal(err)
	}
	select {
	case region := <-observedNetInfo:
		if region != 7 {
			t.Fatalf("network report region=%d", region)
		}
	case <-ready.Done():
		t.Fatal("agent did not supply the live transport's NetInfo to its coordinator fetch")
	}
	if e.healthy.Load() {
		t.Fatal("cached startup with unavailable coordinator enabled DERP home changes")
	}
	p, _ := testState(t, 2)
	s.Peers = []*tailcfg.Node{p.Self}
	s.UpdatedAt = time.Now()
	s.ExpiresAt = s.UpdatedAt.Add(CacheLifetime)
	if err := Update(ctx, dir, s); err != nil {
		t.Fatal(err)
	}
	if e.applied.Load() != 1 {
		t.Fatalf("expected same running engine update, got %d", e.applied.Load())
	}
	restored, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Peers) != 1 {
		t.Fatal("updated trusted peers not persisted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.healthy.Load() {
		t.Fatal("stopped agent retained current control health")
	}
}

func TestRunningAgentRemovesExpiredPeersWithoutRenewingTrust(t *testing.T) {
	s, id := testState(t, 1)
	expired, _ := testState(t, 2)
	expired.Self.KeyExpiry = time.Now().Add(-time.Second)
	s.Peers = []*tailcfg.Node{expired.Self}
	s.DirectHubEndpoints[expired.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:41641")}
	e := &testEngine{closed: make(chan struct{})}
	a := &agent{dir: t.TempDir(), identity: id, state: s, engine: e}
	if err := a.expire(time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.applied.Load() != 1 || len(a.state.Peers) != 0 || len(a.state.DirectHubEndpoints) != 0 {
		t.Fatal("expired peer was not removed from the running transport")
	}
	restored, err := LoadState(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Peers) != 0 || len(restored.DirectHubEndpoints) != 0 {
		t.Fatal("expired peer survived on disk")
	}
	if !restored.UpdatedAt.Equal(s.UpdatedAt) || !restored.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("expiration processing extended the trusted cache window")
	}
	a.state.Self.KeyExpiry = time.Now().Add(-time.Second)
	if err := a.expire(time.Now()); err == nil {
		t.Fatal("expired local identity kept running")
	}
}
