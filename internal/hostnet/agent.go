package hostnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// Fetch performs an authenticated full map request. Its implementation uses
// the coordinator's Tailscale Noise client; it must not trust plaintext maps.
type Fetch func(context.Context, *Identity, *State, []netip.AddrPort) (*tailcfg.MapResponse, error)
type Options struct {
	Fetch Fetch
	Logf  logger.Logf
	// EngineFactory is an integration-test seam; nil uses the real TUN engine.
	EngineFactory func(*State, *Identity, logger.Logf) (Engine, error)
	PollInterval  time.Duration
}

type Status struct {
	Ready     bool
	ClusterID string
	Address   netip.Addr
	Endpoints []netip.AddrPort
	Peers     int
	LastSync  time.Time
	ExpiresAt time.Time
}

type agent struct {
	refreshMu sync.Mutex
	mu        sync.Mutex
	dir       string
	identity  *Identity
	state     *State
	engine    Engine
	options   Options
	// Only a transport timeout followed by a committed authenticated map can
	// trigger revalidation. HTTP/auth failures and cached startup cannot.
	transportTimedOut bool
	networkMu         sync.Mutex
	networkBusy       bool
	networkReadyAt    time.Time
}

func SocketPath(dir string) string { return filepath.Join(dir, "agent.sock") }

// Run restores the trusted snapshot into the engine before exposing readiness
// or contacting any service. The engine remains owned by this process when the
// coordinator becomes available and receives updates in place.
func Run(ctx context.Context, dir string, opts Options) error {
	if opts.Logf == nil {
		opts.Logf = logger.Discard
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	unlock, err := platform.Lock(filepath.Join(dir, "agent-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	id, err := LoadIdentity(dir)
	if err != nil {
		return err
	}
	s, err := LoadState(dir)
	if err != nil {
		return err
	}
	if err = s.Validate(id, time.Now()); err != nil {
		return err
	}
	factory := opts.EngineFactory
	if factory == nil {
		factory = NewEngine
	}
	e, err := factory(s, id, opts.Logf)
	if err != nil {
		return err
	}
	defer e.Close()
	e.SetControlHealthy(false)
	defer e.SetControlHealthy(false)
	// Persist expiration pruning before publishing readiness. This is still the
	// same trusted snapshot and does not extend its offline validity window.
	if err = SaveState(dir, s); err != nil {
		return err
	}
	a := &agent{dir: dir, identity: id, state: s, engine: e, options: opts}
	path := SocketPath(dir)
	if err = platform.CheckPath(path); err != nil {
		return err
	}
	if fi, statErr := os.Lstat(path); statErr == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return errors.New("agent socket path is occupied by a non-socket file")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		return err
	}
	server := &http.Server{Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(l) }()
	opts.Logf("host overlay restored on %s with %d peers", s.Interface, len(s.Peers))
	// Polling also advertises changing NAT endpoints; failures preserve the last
	// trusted state until its explicit deadline. No cluster DNS is involved.
	tick := time.NewTicker(opts.PollInterval)
	defer tick.Stop()
	refresh := make(chan struct{}, 1)
	refresh <- struct{}{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-e.Done():
			return errors.New("host overlay transport stopped unexpectedly")
		case err := <-serverErr:
			return err
		case <-tick.C:
			if err := a.expire(time.Now()); err != nil {
				return fmt.Errorf("trusted overlay expiration: %w", err)
			}
			select {
			case refresh <- struct{}{}:
			default:
			}
		case <-refresh:
			if opts.Fetch == nil {
				continue
			}
			if err := a.refresh(ctx); err != nil && ctx.Err() == nil {
				opts.Logf("coordinator refresh failed; retaining trusted overlay: %v", err)
			}
		}
	}
}

func (a *agent) expire(now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.state.Clone()
	s.pruneExpiredPeers(now)
	if err := s.Validate(a.identity, now); err != nil {
		return err
	}
	if len(s.Peers) != len(a.state.Peers) {
		return a.apply(s)
	}
	return nil
}

func (a *agent) refresh(ctx context.Context) (err error) {
	// Both the timer and local /refresh endpoint enter here. Commit control
	// health and pending path recovery in request order, including failures.
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	healthy := false
	fetchFailed := false
	parentCtx := ctx
	defer func() {
		healthy = healthy && parentCtx.Err() == nil
		a.engine.SetControlHealthy(healthy)
		a.mu.Lock()
		rebind := healthy && a.transportTimedOut
		var timeout net.Error
		if healthy {
			a.transportTimedOut = false
		} else if fetchFailed && parentCtx.Err() == nil && errors.As(err, &timeout) && timeout.Timeout() {
			a.transportTimedOut = true
		}
		a.mu.Unlock()
		if rebind {
			a.engine.Rebind()
		}
	}()
	if a.options.Fetch == nil {
		return errors.New("coordinator synchronization is not configured")
	}
	a.mu.Lock()
	s := a.state.Clone()
	eps := a.engine.Endpoints()
	if info := a.engine.NetInfo(); info != nil {
		hi := s.Self.Hostinfo.AsStruct()
		if hi == nil {
			hi = new(tailcfg.Hostinfo)
		}
		hi.NetInfo = info
		s.Self.Hostinfo = hi.View()
	}
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	m, err := a.options.Fetch(ctx, a.identity, s, eps)
	if err != nil {
		fetchFailed = true
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	n, err := s.WithMap(m, time.Now())
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// A local bootstrap transaction may have raced a request. Fetch again
	// instead of replacing its newer peer state with an older response.
	if !a.state.UpdatedAt.Equal(s.UpdatedAt) {
		return nil
	}
	err = a.apply(n)
	healthy = err == nil && ctx.Err() == nil
	return err
}

func (a *agent) apply(s *State) error {
	if err := s.Validate(a.identity, time.Now()); err != nil {
		return err
	}
	if s.UpdatedAt.Before(a.state.UpdatedAt) {
		return errors.New("refusing an older overlay snapshot")
	}
	if err := a.engine.Apply(s, false); err != nil {
		return errors.Join(err, a.engine.Apply(a.state, true))
	}
	if err := SaveState(a.dir, s); err != nil {
		return errors.Join(err, a.engine.Apply(a.state, true))
	}
	a.state = s.Clone()
	return nil
}

func (a *agent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /network/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.network(r.Context(), networkLimitsDefault))
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Status{Ready: time.Now().Before(a.state.ExpiresAt), ClusterID: a.state.ClusterID, Address: a.state.Self.Addresses[0].Addr(), Endpoints: a.engine.Endpoints(), Peers: len(a.state.Peers), LastSync: a.state.UpdatedAt, ExpiresAt: a.state.ExpiresAt})
	})
	mux.HandleFunc("POST /state", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		var s State
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.apply(&s); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		if err := a.refresh(r.Context()); err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /ping", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
		if err != nil {
			http.Error(w, "invalid peer address", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err = a.engine.Ping(ctx, ip); err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func request(ctx context.Context, dir, method, path string, body any, result any) error {
	var b io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		b = bytes.NewReader(data)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", SocketPath(dir))
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, b)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &agentHTTPError{status: resp.StatusCode, body: string(data)}
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result)
	}
	return nil
}

type agentHTTPError struct {
	status int
	body   string
}

func (e *agentHTTPError) Error() string { return "host agent: " + e.body }

func AgentStatus(ctx context.Context, dir string) (*Status, error) {
	var s Status
	if err := request(ctx, dir, "GET", "/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
func Update(ctx context.Context, dir string, s *State) error {
	return request(ctx, dir, "POST", "/state", s, nil)
}
func Refresh(ctx context.Context, dir string) error {
	return request(ctx, dir, "POST", "/refresh", nil, nil)
}
func VerifyPeer(ctx context.Context, dir string, ip netip.Addr) error {
	return request(ctx, dir, "POST", "/ping?ip="+ip.String(), nil, nil)
}
func WaitReady(ctx context.Context, dir string) error {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if s, err := AgentStatus(ctx, dir); err == nil && s.Ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
