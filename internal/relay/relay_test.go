package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

func TestPersistentRelayIdentityDoesNotRotateOnResumeOrCorruption(t *testing.T) {
	dir := t.TempDir()
	first, err := loadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadIdentity(dir)
	if err != nil || first.Public() != again.Public() {
		t.Fatal("relay identity rotated", err)
	}
	path := filepath.Join(dir, "derp.key")
	if err = os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadIdentity(dir); err == nil {
		t.Fatal("corrupt identity silently replaced")
	}
}

func TestSTUNResponsesAndIdleCancellation(t *testing.T) {
	server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveSTUN(ctx, server) }()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("not a STUN request")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		tx := stun.NewTxID()
		if _, err := client.Write(stun.Request(tx)); err != nil {
			t.Fatal(err)
		}
		var response [1500]byte
		n, err := client.Read(response[:])
		if err != nil {
			t.Fatal(err)
		}
		gotTx, addr, err := stun.ParseResponse(response[:n])
		if err != nil || gotTx != tx || addr != client.LocalAddr().(*net.UDPAddr).AddrPort() {
			t.Fatalf("incorrect binding response: tx=%v addr=%v err=%v", gotTx, addr, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("idle cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not wake the idle reader")
	}
}

func TestSTUNClosedSocketReturnsError(t *testing.T) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := serveSTUN(context.Background(), conn); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed socket: %v", err)
	}
}
func TestRelayRefusesUnauthenticatedRemoteAdmissionAndPublicPlaintext(t *testing.T) {
	for _, c := range []Config{{VerifyURL: "http://control.example.com/verify"}, {VerifyURL: "https://control.example.com/verify", StateDir: t.TempDir(), Listen: "0.0.0.0:3340"}} {
		if err := Run(context.Background(), c); err == nil {
			t.Fatal("insecure relay configuration accepted")
		}
	}
}
