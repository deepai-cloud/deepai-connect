//go:build vpsintegration

package coordinator

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestVPSDenialRequiresFreshConnectionAndRequestDeadline(t *testing.T) {
	dials := 0
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials++
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	for range 2 {
		if err := vpsCheckDenied(context.Background(), client, vpsTarget{url: "http://100.96.0.1/"}, 25*time.Millisecond, false); err != nil {
			t.Fatal(err)
		}
	}
	if dials != 2 {
		t.Fatalf("denial reused an earlier flow: dials=%d", dials)
	}
}

func TestVPSPolicyRejectRequiresExactStructuredConnectError(t *testing.T) {
	target, _ := url.Parse("http://100.96.0.7:8080/")
	refused := &net.OpError{Op: "connect", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("100.96.0.7"), Port: 8080}, Err: errors.New("connection was refused")}
	if !vpsIsPolicyReject(refused, target) {
		t.Fatal("upstream structured refusal was rejected")
	}
	for _, err := range []error{
		errors.New("connection was refused"),
		&net.OpError{Op: "read", Net: refused.Net, Addr: refused.Addr, Err: refused.Err},
		&net.OpError{Op: refused.Op, Net: "udp", Addr: refused.Addr, Err: refused.Err},
		&net.OpError{Op: refused.Op, Net: refused.Net, Addr: &net.TCPAddr{IP: net.ParseIP("100.96.0.8"), Port: 8080}, Err: refused.Err},
		&net.OpError{Op: refused.Op, Net: refused.Net, Addr: refused.Addr, Err: errors.New("network is unreachable")},
	} {
		if vpsIsPolicyReject(err, target) {
			t.Errorf("unrelated error accepted as policy refusal: %v", err)
		}
	}
}

func TestVPSDenialRejectsResponsesAndImmediateNetworkErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{}}
	if err := vpsCheckDenied(context.Background(), client, vpsTarget{url: srv.URL}, time.Second, false); err == nil {
		t.Fatal("HTTP rejection was accepted as a network-policy timeout")
	}
	client.Transport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }}
	if err := vpsCheckDenied(context.Background(), client, vpsTarget{url: srv.URL}, time.Second, false); err == nil {
		t.Fatal("an arbitrary network error was accepted as a policy denial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := vpsCheckDenied(ctx, client, vpsTarget{url: srv.URL}, time.Second, false); err == nil {
		t.Fatal("overall test cancellation was accepted as a policy denial")
	}
}
