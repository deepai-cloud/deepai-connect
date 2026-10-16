//go:build integration

package coordinator

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
)

// This uses unmodified upstream clients and real userspace WireGuard transports.
// It requires no root privileges, host network changes, Kubernetes, or public
// coordinator. Run with: go test -tags=integration ./internal/coordinator.
func TestUpstreamClientsExchangeEncryptedTraffic(t *testing.T) {
	if mode := os.Getenv(nativeChildMode); mode != "" {
		if mode != "automatic_path" && mode != "forced_derp_fallback" {
			t.Fatal("invalid native interoperability child mode")
		}
		nativeRoundTrip(t, mode == "forced_derp_fallback")
		return
	}
	for _, mode := range []string{"automatic_path", "forced_derp_fallback"} {
		t.Run(mode, func(t *testing.T) {
			runNativeTestProcess(t, mode, 45*time.Second, "TS_DEBUG_OMIT_LOCAL_ADDRS="+strconv.FormatBool(mode == "forced_derp_fallback"))
		})
	}
}

func nativeRoundTrip(t *testing.T, forceDERP bool) {
	// The forced-DERP child omits local endpoints and disables STUN below,
	// so peers must exchange encrypted packets through the real relay sockets.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, control := newServer(t, &MemoryStore{})
	relay := derpserver.New(key.NewNode(), t.Logf)
	relayHTTP := httptest.NewTLSServer(derpserver.Handler(relay))
	t.Cleanup(func() { relay.Close(); relayHTTP.Close() })
	host, portString, _ := net.SplitHostPort(relayHTTP.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	if err := s.Update(ctx, func(st *State) error {
		st.DERPMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "local", RegionName: "Local test", Nodes: []*tailcfg.DERPNode{{Name: "1a", RegionID: 1, HostName: host, IPv4: host, IPv6: "none", DERPPort: port, STUNPort: -1, InsecureForTests: true}}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateInvitation(ctx, Invitation{Role: "client", UsesRemaining: 2})
	if err != nil {
		t.Fatal(err)
	}
	a := &tsnet.Server{Dir: t.TempDir(), Hostname: "native-a", ControlURL: control.URL, AuthKey: token, Logf: t.Logf, UserLogf: t.Logf}
	b := &tsnet.Server{Dir: t.TempDir(), Hostname: "native-b", ControlURL: control.URL, AuthKey: token, Logf: t.Logf, UserLogf: t.Logf}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if _, err = a.Up(ctx); err != nil {
		t.Fatalf("first native client: %v", err)
	}
	status, err := b.Up(ctx)
	if err != nil {
		t.Fatalf("second native client: %v", err)
	}
	listener, err := b.Listen("tcp", ":8087")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "native WireGuard round trip") })}
	defer server.Close()
	go server.Serve(listener)
	client := &http.Client{Transport: &http.Transport{DialContext: a.Dial}}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(status.TailscaleIPs[0].String(), "8087"), nil)
	reply, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "native WireGuard round trip" {
		t.Fatalf("unexpected encrypted response: %q", body)
	}
	if forceDERP {
		local, err := a.LocalClient()
		if err != nil {
			t.Fatal(err)
		}
		probe, done := context.WithTimeout(ctx, 5*time.Second)
		ping, err := local.Ping(probe, status.TailscaleIPs[0], tailcfg.PingDisco)
		done()
		if err != nil || ping == nil || ping.Err != "" || ping.DERPRegionID != 1 || ping.Endpoint != "" {
			t.Fatalf("native discovery failed to identify forced DERP path: result=%+v error=%v", ping, err)
		}
		var stats map[string]json.RawMessage
		if err := json.Unmarshal([]byte(relay.ExpVar(false).String()), &stats); err != nil {
			t.Fatal(err)
		}
		var sent int64
		if err := json.Unmarshal(stats["packets_sent"], &sent); err != nil || sent == 0 {
			t.Fatal("forced fallback sent no packets through the relay")
		}
	}
}
