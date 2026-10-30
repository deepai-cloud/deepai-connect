package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Exercise the actual HTTP/2 settings and map handler with an authenticated
// fixture context. The raw peer can keep reading data while withholding PING
// acknowledgements, unlike an ordinary HTTP/2 client that always answers them.
// Virtual time avoids slowing the suite or disrupting any enrolled device.
func TestMapPresenceRequiresResponsiveControlPeer(t *testing.T) {
	for _, keepAlive := range []bool{false, true} {
		t.Run(fmt.Sprintf("keepalive=%t", keepAlive), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, store, node, machine, nodeKey := presenceFixture(t)
				defer s.Close()
				peer := startPresencePeer(t, s, machine, nodeKey, keepAlive)
				defer peer.close()
				synctest.Wait()

				// A quiet but responsive stream remains connected across both
				// health-check and heartbeat intervals.
				time.Sleep(75 * time.Second)
				synctest.Wait()
				select {
				case <-peer.serverDone:
					t.Fatal("healthy idle control stream was closed")
				default:
				}
				if peer.pings.Load() < 2 {
					t.Fatal("idle stream was not checked with HTTP/2 PING")
				}
				seen := presenceLastSeen(t, store, machine)
				if time.Since(seen) > 25*time.Second {
					t.Fatal("healthy idle stream stopped refreshing presence")
				}

				// Keep the receive path open, but stop proving client liveness.
				// Writes still succeed; only the missing PING ACK exposes this.
				peer.ackPings.Store(false)
				time.Sleep(41 * time.Second)
				synctest.Wait()
				select {
				case <-peer.serverDone:
				default:
					t.Fatal("unresponsive peer retained a map stream past the 40-second bound")
				}
				seen = presenceLastSeen(t, store, machine)
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				if later := presenceLastSeen(t, store, machine); !later.Equal(seen) {
					t.Fatal("failed stream continued refreshing LastSeen")
				}
				st, err := store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				m, err := MapForState(st, machine.Public().String())
				if err != nil || m.Node.Online == nil || *m.Node.Online {
					t.Fatalf("disconnected identity must remain registered but offline: %v", err)
				}
				if len(st.Nodes) != 1 || uint64(m.Node.ID) != node.ID {
					t.Fatal("disconnect changed registered identity")
				}

				// Reconnecting with the original keys restores the same ID.
				reconnected := startPresencePeer(t, s, machine, nodeKey, keepAlive)
				defer reconnected.close()
				synctest.Wait()
				st, err = store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				m, err = MapForState(st, machine.Public().String())
				if err != nil || m.Node.Online == nil || !*m.Node.Online || uint64(m.Node.ID) != node.ID || len(st.Nodes) != 1 {
					t.Fatalf("reconnect did not preserve and reactivate identity: %v", err)
				}
			})
		})
	}
}

func TestFailedHeartbeatDoesNotRefreshPresence(t *testing.T) {
	for _, keepAlive := range []bool{false, true} {
		t.Run(fmt.Sprintf("keepalive=%t", keepAlive), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, store, _, machine, nodeKey := presenceFixture(t)
				defer s.Close()
				body, err := json.Marshal(tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public(), Stream: true, KeepAlive: keepAlive})
				if err != nil {
					t.Fatal(err)
				}
				w := &failingPresenceWriter{ResponseRecorder: httptest.NewRecorder(), failAt: time.Now().Add(25 * time.Second)}
				done := make(chan struct{})
				go func() {
					defer close(done)
					s.serveMap(w, httptest.NewRequest("POST", "/machine/map", bytes.NewReader(body)), machine.Public())
				}()
				synctest.Wait()
				seen := presenceLastSeen(t, store, machine)
				time.Sleep(26 * time.Second)
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("failed heartbeat did not stop the stream")
				}
				if later := presenceLastSeen(t, store, machine); !later.Equal(seen) {
					t.Fatal("failed heartbeat refreshed LastSeen before its failed flush")
				}
			})
		})
	}
}

func TestControlConnectionClosesOnWriteStall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		h2 := controlHTTP2Server()
		base := &http.Server{}
		if err := http2.ConfigureServer(base, h2); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			h2.ServeConn(server, &http2.ServeConnOpts{BaseConfig: base})
		}()
		if _, err := io.WriteString(client, http2.ClientPreface); err != nil {
			t.Fatal(err)
		}
		if err := http2.NewFramer(client, nil).WriteSettings(); err != nil {
			t.Fatal(err)
		}
		// The peer never reads the server's settings, so its write stalls.
		time.Sleep(16 * time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("blocked control transport exceeded the 15-second write timeout")
		}
	})
}

type failingPresenceWriter struct {
	*httptest.ResponseRecorder
	failAt time.Time
}

func (w *failingPresenceWriter) FlushError() error {
	if !time.Now().Before(w.failAt) {
		return errors.New("fixture stream disconnected")
	}
	w.Flush()
	return nil
}

func presenceFixture(t *testing.T) (*Server, *MemoryStore, Node, key.MachinePrivate, key.NodePrivate) {
	t.Helper()
	st := NewState()
	node, machine, nodeKey := testIdentity("client")
	if err := AllocateNode(st, &node); err != nil {
		t.Fatal(err)
	}
	store := &MemoryStore{}
	if err := store.CompareAndSwap(context.Background(), st, ""); err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), Config{Store: store, PollInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s, store, node, machine, nodeKey
}

func presenceLastSeen(t *testing.T, store *MemoryStore, machine key.MachinePrivate) time.Time {
	t.Helper()
	st, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st.Nodes[machine.Public().String()].LastSeen
}

type presencePeer struct {
	client     net.Conn
	server     net.Conn
	serverDone chan struct{}
	ackPings   atomic.Bool
	pings      atomic.Int64
}

func (p *presencePeer) close() {
	_ = p.client.Close()
	_ = p.server.Close()
}

func startPresencePeer(t *testing.T, s *Server, machine key.MachinePrivate, nodeKey key.NodePrivate, keepAlive bool) *presencePeer {
	t.Helper()
	server, client := net.Pipe()
	p := &presencePeer{client: client, server: server, serverDone: make(chan struct{})}
	p.ackPings.Store(true)
	h2 := controlHTTP2Server()
	base := &http.Server{Handler: http.HandlerFunc(s.serveMachine)}
	// Initialize private HTTP/2 pools so channels cannot cross synctest bubbles.
	if err := http2.ConfigureServer(base, h2); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.serverDone)
		h2.ServeConn(server, &http2.ServeConnOpts{
			Context:    context.WithValue(context.Background(), machineContextKey{}, machine.Public()),
			BaseConfig: base,
		})
	}()
	writer := http2.NewFramer(client, nil)
	var writeMu sync.Mutex
	writeMu.Lock()
	defer writeMu.Unlock()
	go func() {
		reader := http2.NewFramer(nil, client)
		for {
			frame, err := reader.ReadFrame()
			if err != nil {
				return
			}
			writeMu.Lock()
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					err = writer.WriteSettingsAck()
				}
			case *http2.PingFrame:
				if !f.IsAck() {
					p.pings.Add(1)
					if p.ackPings.Load() {
						err = writer.WritePing(true, f.Data)
					}
				}
			}
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	body, err := json.Marshal(tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public(), Stream: true, KeepAlive: keepAlive})
	if err != nil {
		t.Fatal(err)
	}
	var headers bytes.Buffer
	encoder := hpack.NewEncoder(&headers)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "fixture"}, {Name: ":path", Value: "/machine/map"}} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(client, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: headers.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteData(1, true, body); err != nil {
		t.Fatal(err)
	}
	return p
}
