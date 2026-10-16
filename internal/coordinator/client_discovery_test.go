package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// A changed NAT path can silently discard writes on an established connection
// while new connections to the same server remain healthy.
type discoveryConn struct {
	net.Conn
	blackhole atomic.Bool
	closed    chan struct{}
	once      sync.Once
}

func (c *discoveryConn) Write(b []byte) (int, error) {
	if c.blackhole.Load() {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *discoveryConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestDiscoveryDoesNotReuseStaleHTTP2(t *testing.T) {
	serverKey := key.NewMachine().Public()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("discovery used %s, want HTTP/2", r.Proto)
		}
		json.NewEncoder(w).Encode(tailcfg.OverTLSPublicKeyResponse{PublicKey: serverKey})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	defer transport.CloseIdleConnections()
	var mu sync.Mutex
	var conns []*discoveryConn
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tracked := &discoveryConn{Conn: conn, closed: make(chan struct{})}
		mu.Lock()
		conns = append(conns, tracked)
		mu.Unlock()
		return tracked, nil
	}
	connections := func() []*discoveryConn {
		mu.Lock()
		defer mu.Unlock()
		return append([]*discoveryConn(nil), conns...)
	}
	shared := &http.Client{Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/key", nil)
	res, err := shared.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if got := connections(); len(got) != 1 {
		t.Fatalf("priming made %d connections, want 1", len(got))
	}
	stale := connections()[0]
	stale.blackhole.Store(true)
	assertStale := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/key", nil)
		res, err := shared.Do(req)
		if res != nil {
			res.Body.Close()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blackholed pooled request: %v, want deadline", err)
		}
		select {
		case <-stale.closed:
			t.Fatal("pooled HTTP/2 connection closed; stale-pool condition not reproduced")
		default:
		}
	}
	assertStale()
	u, _ := url.Parse(server.URL)
	client := &Client{ServerURL: server.URL, HTTPClient: shared}
	for i := 0; i < 2; i++ {
		got, err := client.fetchKey(ctx, u)
		if err != nil || got != serverKey {
			t.Fatalf("discovery %d with stale shared pool: key=%v err=%v", i, got, err)
		}
		all := connections()
		if len(all) != i+2 {
			t.Fatalf("discovery %d made %d connections, want %d", i, len(all), i+2)
		}
		select {
		case <-all[len(all)-1].closed:
		case <-ctx.Done():
			t.Fatal("successful discovery did not close its owned connection")
		}
	}
	// Discovery must neither reuse nor close its caller's pooled connection.
	assertStale()
}

func TestDiscoveryTimeoutClosesOwnedHTTP2Connection(t *testing.T) {
	serverKey := key.NewMachine().Public()
	var requests atomic.Int32
	serverCanceled := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("discovery used %s, want HTTP/2", r.Proto)
		}
		if requests.Add(1) == 1 {
			io.WriteString(w, `{"publicKey":`)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(serverCanceled)
			return
		}
		json.NewEncoder(w).Encode(tailcfg.OverTLSPublicKeyResponse{PublicKey: serverKey})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	defer transport.CloseIdleConnections()
	connections := make(chan *discoveryConn, 2)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tracked := &discoveryConn{Conn: conn, closed: make(chan struct{})}
		connections <- tracked
		return tracked, nil
	}
	u, _ := url.Parse(server.URL)
	client := &Client{ServerURL: server.URL, HTTPClient: &http.Client{Transport: transport}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err := client.fetchKey(ctx, u)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("partial discovery body: %v, want deadline", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var first *discoveryConn
	select {
	case first = <-connections:
	case <-ctx.Done():
		t.Fatal("discovery never connected")
	}
	select {
	case <-first.closed:
	case <-ctx.Done():
		t.Fatal("timed-out discovery did not close its owned connection")
	}
	select {
	case <-serverCanceled:
	case <-ctx.Done():
		t.Fatal("timed-out discovery left its server stream running")
	}
	got, err := client.fetchKey(ctx, u)
	if err != nil || got != serverKey {
		t.Fatalf("discovery after timeout: key=%v err=%v", got, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("received %d discovery requests, want 2", requests.Load())
	}
}
