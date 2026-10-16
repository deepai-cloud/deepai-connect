//go:build vpsintegration

package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// TestVPSNativeInteroperability is opt-in: it uses real upstream tsnet over the
// public coordinator and real VPS host/pod/service routes. It never connects
// through SSH, changes the host network, or starts another system daemon.
//
// Required environment (all names begin DEEPAI_VPS_):
//
//	CONTROL_URL, AUTH_KEY_FILE (private raw client auth key), POD_URL,
//	SERVICE_URL, HUB_URL, and EXPECT_BODY (the exact common response body).
//
// Per-endpoint POD_BODY/SERVICE_BODY/HUB_BODY override EXPECT_BODY. Alternatively
// *_SHA256 supplies the SHA-256 of that endpoint's expected bytes (useful for the
// hub's signed /probe response). URLs must use private IPv4 addresses and HTTP.
// Each payload check makes one request; transport errors, partial responses,
// unexpected status codes, and incorrect payloads fail without retries.
//
// Optional: STATE_DIR preserves the native identity across runs; DURATION=5m
// repeats requests on one live client; BARRIER_FILE pauses after the baseline,
// creates BARRIER_FILE.ready, and continues when the caller creates BARRIER_FILE.
// The caller can stop coordinators/relays during this pause. EXPECT_PATH and
// AFTER_PATH can require direct or derp transport; the default reports either.
// EXPECT_DENIED_AFTER_BARRIER=POD,SERVICE requires fresh requests to those
// endpoints to reach their three-second deadlines after the barrier. Responses,
// connection refusals, and other errors fail; HUB remains a positive control.
// ALLOW_POLICY_REJECT=1 additionally accepts the exact upstream gVisor TCP
// connection-refused result for that target. Use this only with independently
// observed Kubernetes REJECT counter increments and successful payload checks
// after removing the test policy; arbitrary transport failures never count.
// NATIVE_ENDPOINT_FILE starts a private HTTP listener on this client's IPv4
// address, port 18081, serving EXPECT_BODY. It exclusively creates the requested
// 0600 file in an existing private directory with the endpoint URL, and keeps
// the listener alive throughout BARRIER_FILE/DURATION. The file contains no
// credentials and is removed when the test finishes.
// TIMEOUT defaults to 10m and bounds the whole test. Run with:
//
//	go test -tags=vpsintegration -run '^TestVPSNativeInteroperability$' \
//	  -count=1 -v -timeout=15m ./internal/coordinator
func TestVPSNativeInteroperability(t *testing.T) {
	control := os.Getenv("DEEPAI_VPS_CONTROL_URL")
	if control == "" {
		t.Skip("set DEEPAI_VPS_CONTROL_URL to opt in to the real VPS test")
	}
	if os.Getenv(nativeChildMode) != "external-vps" {
		runNativeTestProcess(t, "external-vps", vpsDuration(t, "TIMEOUT", 10*time.Minute)+30*time.Second)
		return
	}
	u, err := url.Parse(control)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		t.Fatal("CONTROL_URL must be an authenticated HTTPS origin")
	}
	keyPath := os.Getenv("DEEPAI_VPS_AUTH_KEY_FILE")
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("AUTH_KEY_FILE must be an existing private regular file (0600 or 0400)")
	}
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal("cannot read private AUTH_KEY_FILE")
	}
	token := strings.TrimSpace(string(rawKey))
	if !strings.HasPrefix(token, "dai-") || len(token) != 68 {
		t.Fatal("AUTH_KEY_FILE must contain one raw Connect native-client auth key")
	}
	var targets []vpsTarget
	for _, name := range []string{"POD", "SERVICE", "HUB"} {
		target, err := vpsTargetFromEnv(name)
		if err != nil {
			t.Fatalf("%s target configuration: %v", name, err)
		}
		targets = append(targets, target)
	}
	denied := map[string]bool{}
	if raw := os.Getenv("DEEPAI_VPS_EXPECT_DENIED_AFTER_BARRIER"); raw != "" {
		if os.Getenv("DEEPAI_VPS_BARRIER_FILE") == "" {
			t.Fatal("EXPECT_DENIED_AFTER_BARRIER requires BARRIER_FILE")
		}
		for _, name := range strings.Split(raw, ",") {
			if (name != "POD" && name != "SERVICE") || denied[name] {
				t.Fatal("EXPECT_DENIED_AFTER_BARRIER accepts POD and SERVICE once each; HUB must remain reachable")
			}
			denied[name] = true
		}
	}
	nativeEndpointFile := os.Getenv("DEEPAI_VPS_NATIVE_ENDPOINT_FILE")
	var nativeBody string
	if nativeEndpointFile != "" {
		var present bool
		nativeBody, present = os.LookupEnv("DEEPAI_VPS_EXPECT_BODY")
		if !present {
			t.Fatal("NATIVE_ENDPOINT_FILE requires EXPECT_BODY for its response payload")
		}
		if err := vpsValidateNativeEndpointFile(nativeEndpointFile); err != nil {
			t.Fatal(err)
		}
	}
	timeout := vpsDuration(t, "TIMEOUT", 10*time.Minute)
	duration := vpsDuration(t, "DURATION", 0)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stateDir := os.Getenv("DEEPAI_VPS_STATE_DIR")
	if stateDir == "" {
		stateDir = t.TempDir()
	} else {
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			t.Fatal("cannot create private STATE_DIR")
		}
		fi, err := os.Lstat(stateDir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
			t.Fatal("STATE_DIR must be a private directory (0700)")
		}
	}
	quiet := func(string, ...any) {}
	srv := &tsnet.Server{Dir: stateDir, Hostname: "connect-vps-validation", ControlURL: control, AuthKey: token, Logf: quiet, UserLogf: quiet}
	defer srv.Close()
	if _, err := srv.Up(ctx); err != nil {
		t.Fatalf("native client connection: %s", strings.ReplaceAll(err.Error(), token, "[REDACTED]"))
	}
	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatal("native local API unavailable")
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{RouteAllSet: true, Prefs: ipn.Prefs{RouteAll: true}}); err != nil {
		t.Fatalf("accept approved subnet routes: %v", err)
	}
	if nativeEndpointFile != "" {
		ip4, _ := srv.TailscaleIPs()
		closeEndpoint, err := vpsStartNativeEndpoint(t, srv.Listen, ip4, nativeEndpointFile, nativeBody)
		if err != nil {
			t.Fatalf("native reverse-path endpoint: %v", err)
		}
		defer closeEndpoint()
		t.Logf("native reverse-path listener ready; URL recorded in %s", filepath.Base(nativeEndpointFile))
	}
	client := &http.Client{Transport: &http.Transport{DialContext: srv.Dial}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("test endpoint redirect forbidden") }}
	defer client.CloseIdleConnections()
	round := func(phase, expectedPath string) {
		t.Helper()
		beforeRX, beforeTX := vpsCounters(t, ctx, lc)
		for _, target := range targets {
			start := time.Now()
			if phase != "baseline" && denied[target.name] {
				if err := vpsCheckDenied(ctx, client, target, 3*time.Second, os.Getenv("DEEPAI_VPS_ALLOW_POLICY_REJECT") == "1"); err != nil {
					t.Fatalf("%s %s denial: %v", phase, target.name, err)
				}
				t.Logf("%s %s: fresh HTTP request denied in %s (policy-reject acceptance=%t)", phase, target.name, time.Since(start).Round(time.Millisecond), os.Getenv("DEEPAI_VPS_ALLOW_POLICY_REJECT") == "1")
				continue
			}
			probe, done := context.WithTimeout(ctx, 30*time.Second)
			t.Logf("%s %s: request started at %s", phase, target.name, start.UTC().Format(time.RFC3339Nano))
			probe = httptrace.WithClientTrace(probe, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				t.Logf("%s %s: TCP %s -> %s (reused=%t)", phase, target.name, info.Conn.LocalAddr(), info.Conn.RemoteAddr(), info.Reused)
			}})
			err := vpsCheckPayload(probe, client, target)
			done()
			if err != nil {
				t.Fatalf("%s %s: %v", phase, target.name, err)
			}
			t.Logf("%s %s: expected payload verified over WireGuard in %s", phase, target.name, time.Since(start).Round(time.Millisecond))
		}
		afterRX, afterTX := vpsCounters(t, ctx, lc)
		if afterRX <= beforeRX || afterTX <= beforeTX {
			t.Fatal("HTTP succeeded without increasing native WireGuard receive/transmit counters")
		}
		t.Logf("%s encrypted traffic: received=%d transmitted=%d bytes", phase, afterRX-beforeRX, afterTX-beforeTX)
		vpsReportPath(t, ctx, lc, targets[2].ip, phase, expectedPath)
	}
	round("baseline", os.Getenv("DEEPAI_VPS_EXPECT_PATH"))
	if barrier := os.Getenv("DEEPAI_VPS_BARRIER_FILE"); barrier != "" {
		if _, err := os.Lstat(barrier); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("BARRIER_FILE must not already exist")
		}
		ready := barrier + ".ready"
		f, err := os.OpenFile(ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("cannot create exclusive BARRIER_FILE.ready marker; choose a fresh path in a private directory")
		}
		_, _ = io.WriteString(f, "native overlay baseline passed; client remains connected\n")
		_ = f.Close()
		defer os.Remove(ready)
		t.Logf("baseline ready; waiting for %s while retaining native session", filepath.Base(barrier))
		for {
			fi, err := os.Lstat(barrier)
			if err == nil {
				if !fi.Mode().IsRegular() {
					t.Fatal("BARRIER_FILE must be a regular file")
				}
				break
			}
			if !errors.Is(err, os.ErrNotExist) || !vpsWait(ctx, 250*time.Millisecond) {
				t.Fatal("manual outage barrier failed or timed out")
			}
		}
		round("after-barrier", os.Getenv("DEEPAI_VPS_AFTER_PATH"))
	}
	for until := time.Now().Add(duration); time.Now().Before(until); {
		if !vpsWait(ctx, 2*time.Second) {
			t.Fatal("VPS validation deadline exceeded")
		}
		round("continuous", os.Getenv("DEEPAI_VPS_AFTER_PATH"))
	}
}

func vpsValidateNativeEndpointFile(path string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return errors.New("NATIVE_ENDPOINT_FILE must be inside an existing private directory (0700)")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("NATIVE_ENDPOINT_FILE must not already exist")
	}
	return nil
}

func vpsStartNativeEndpoint(t *testing.T, listen func(string, string) (net.Listener, error), ip netip.Addr, path, body string) (func(), error) {
	t.Helper()
	if !ip.Is4() || (!ip.IsPrivate() && !netip.MustParsePrefix(DefaultNetwork).Contains(ip)) {
		return nil, errors.New("native client has no private overlay IPv4 address")
	}
	if err := vpsValidateNativeEndpointFile(path); err != nil {
		return nil, err
	}
	address := net.JoinHostPort(ip.String(), "18081")
	l, err := listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.Logf("native reverse HTTP request: source=%s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, body)
	})}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = l.Close()
		return nil, errors.New("cannot create exclusive NATIVE_ENDPOINT_FILE")
	}
	_, writeErr := io.WriteString(f, "http://"+address+"/\n")
	err = errors.Join(writeErr, f.Close())
	if err != nil {
		_ = l.Close()
		_ = os.Remove(path)
		return nil, errors.New("cannot write NATIVE_ENDPOINT_FILE")
	}
	go server.Serve(l)
	var closeOnce sync.Once
	return func() {
		closeOnce.Do(func() {
			_ = server.Close()
			_ = os.Remove(path)
		})
	}, nil
}

type vpsTarget struct {
	name, url string
	ip        netip.Addr
	digest    [32]byte
}

func vpsTargetFromEnv(name string) (vpsTarget, error) {
	target := vpsTarget{name: name, url: os.Getenv("DEEPAI_VPS_" + name + "_URL")}
	u, err := url.Parse(target.url)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		return target, errors.New("URL must be an HTTP private-IP endpoint without user information")
	}
	target.ip, err = netip.ParseAddr(u.Hostname())
	if err != nil || !target.ip.Is4() || (!target.ip.IsPrivate() && !netip.MustParsePrefix(DefaultNetwork).Contains(target.ip)) {
		return target, errors.New("URL must use a private or overlay IPv4 address")
	}
	if digest := os.Getenv("DEEPAI_VPS_" + name + "_SHA256"); digest != "" {
		b, err := hex.DecodeString(digest)
		if err != nil || len(b) != sha256.Size {
			return target, errors.New("SHA256 must be exactly 64 hexadecimal characters")
		}
		copy(target.digest[:], b)
	} else {
		body, present := os.LookupEnv("DEEPAI_VPS_" + name + "_BODY")
		if !present {
			body, present = os.LookupEnv("DEEPAI_VPS_EXPECT_BODY")
		}
		if !present {
			return target, errors.New("set EXPECT_BODY, endpoint BODY, or endpoint SHA256")
		}
		target.digest = sha256.Sum256([]byte(body))
	}
	return target, nil
}

func vpsCheckPayload(ctx context.Context, client *http.Client, target vpsTarget) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("private HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("private HTTP response status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("private HTTP response failed after %d bytes: %w", len(body), err)
	}
	if sha256.Sum256(body) != target.digest {
		return fmt.Errorf("response payload differs from the expected bytes (received %d bytes)", len(body))
	}
	return nil
}

func vpsCheckDenied(ctx context.Context, client *http.Client, target vpsTarget, timeout time.Duration, allowPolicyReject bool) error {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return errors.New("denial check requires the native HTTP transport")
	}
	// A new transport guarantees a new connection, avoiding established-flow
	// exemptions in Kubernetes ingress policies and any previous HTTP keepalive.
	fresh := transport.Clone()
	fresh.DisableKeepAlives = true
	defer fresh.CloseIdleConnections()
	probe, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probe, http.MethodGet, target.url, nil)
	if err != nil {
		return err
	}
	isolated := &http.Client{Transport: fresh, CheckRedirect: client.CheckRedirect}
	resp, err := isolated.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
		return fmt.Errorf("unexpected HTTP response with status %d", resp.StatusCode)
	}
	if ctx.Err() != nil {
		return errors.New("overall test deadline expired during denial check")
	}
	if allowPolicyReject && vpsIsPolicyReject(err, req.URL) {
		return nil
	}
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(probe.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("expected the request deadline, got %v", err)
	}
	return nil
}

func vpsIsPolicyReject(err error, target *url.URL) bool {
	var failure *net.OpError
	if !errors.As(err, &failure) || failure.Op != "connect" || failure.Net != "tcp" || failure.Addr == nil || failure.Err == nil || failure.Err.Error() != "connection was refused" {
		return false
	}
	port := target.Port()
	if port == "" {
		port = "80"
	}
	// Pinned upstream gonet discards tcpip.ErrConnectionRefused's type and
	// wraps its exact text in net.OpError. Require both the operation and the
	// target socket; a text-only or unrelated network error is insufficient.
	return failure.Addr.String() == net.JoinHostPort(target.Hostname(), port)
}

func vpsCounters(t *testing.T, ctx context.Context, lc *local.Client) (rx, tx int64) {
	t.Helper()
	status, err := lc.Status(ctx)
	if err != nil {
		t.Fatal("cannot read native encrypted-traffic statistics")
	}
	for _, peer := range status.Peer {
		rx += peer.RxBytes
		tx += peer.TxBytes
	}
	return
}

func vpsReportPath(t *testing.T, ctx context.Context, lc *local.Client, ip netip.Addr, phase, expected string) {
	t.Helper()
	if expected != "" && expected != "direct" && expected != "derp" {
		t.Fatal("EXPECT_PATH and AFTER_PATH must be direct or derp when set")
	}
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	attempts := 0
	last := "no discovery ping attempted"
	lastReply := "no successful discovery reply"
	for {
		attempts++
		attempt, done := context.WithTimeout(probe, 3*time.Second)
		result, err := lc.Ping(attempt, ip, tailcfg.PingDisco)
		done()
		last = vpsPingDiagnostic(result, err)
		if err == nil && result != nil && result.Err == "" {
			lastReply = last
			path := "unknown"
			if result.Endpoint != "" {
				path = "direct"
			} else if result.DERPRegionID != 0 {
				path = "derp"
			}
			if path != "unknown" && (expected == "" || path == expected) {
				t.Logf("%s path=%s endpoint=%s derp-region=%d latency=%s", phase, path, result.Endpoint, result.DERPRegionID, time.Duration(result.LatencySeconds*float64(time.Second)).Round(time.Millisecond))
				return
			}
		}
		if !vpsWait(probe, 250*time.Millisecond) {
			statusCtx, stopStatus := context.WithTimeout(ctx, 2*time.Second)
			status, statusErr := lc.Status(statusCtx)
			stopStatus()
			if statusErr == nil {
				for _, peer := range status.Peer {
					for _, address := range peer.TailscaleIPs {
						if address == ip {
							t.Logf("%s target status: ip=%s online=%t active=%t direct=%q relay=%q peer-relay=%q rx=%d tx=%d", phase, ip, peer.Online, peer.Active, peer.CurAddr, peer.Relay, peer.PeerRelay, peer.RxBytes, peer.TxBytes)
						}
					}
				}
			}
			t.Fatalf("%s could not confirm requested native transport path %q after %d discovery pings; last: %s; last successful reply: %s", phase, expected, attempts, last, lastReply)
		}
	}
}

// Keep failure evidence restricted to the discovery response. Never dump the
// client preferences, key material, full map, or HTTP request headers.
func vpsPingDiagnostic(result *ipnstate.PingResult, err error) string {
	if err != nil {
		message := err.Error()
		if len(message) > 512 {
			message = message[:512]
		}
		return fmt.Sprintf("local API error=%q", message)
	}
	if result == nil {
		return "local API returned no ping result"
	}
	return fmt.Sprintf("ip=%s node-ip=%s error=%q direct=%q derp-region=%d peer-relay=%q local=%t latency=%s", result.IP, result.NodeIP, result.Err, result.Endpoint, result.DERPRegionID, result.PeerRelay, result.IsLocalIP, time.Duration(result.LatencySeconds*float64(time.Second)).Round(time.Millisecond))
}

func vpsDuration(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	if raw := os.Getenv("DEEPAI_VPS_" + name); raw != "" {
		duration, err := time.ParseDuration(raw)
		if err != nil || duration < 0 || duration > time.Hour || (name == "TIMEOUT" && duration == 0) {
			t.Fatal(fmt.Sprintf("%s must be a valid duration up to 1h", name))
		}
		return duration
	}
	return fallback
}

func vpsWait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
