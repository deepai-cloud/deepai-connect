package connect

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"github.com/deepai-cloud/deepai-connect/internal/runtime/docker"
)

// Uses only this test's random names/volumes and random loopback host ports.
// Caddy's test CA replaces public ACME so no real domain or VPS is needed.
func TestLiveConnect(t *testing.T) {
	if os.Getenv("DEEPAI_TEST_CONNECT") != "1" {
		t.Skip("set DEEPAI_TEST_CONNECT=1 for disposable Docker integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d := docker.Client{Run: docker.Run}
	info, err := d.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	run := docker.LocalRunner(info.Endpoint)
	h := fixture(t)
	h.Docker.Endpoint = info.Endpoint
	streamUpstream := ""
	if os.Getenv("DEEPAI_TEST_CADDY_STREAM") == "1" {
		backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, e := io.ReadAll(r.Body); e != nil {
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(65 * time.Second):
			}
			fmt.Fprint(w, "data: after65s\n\n")
		}))
		backend.Listener.Close()
		backend.Listener, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		backend.Start()
		defer backend.Close()
		_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())
		streamUpstream = "host.docker.internal:" + port
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, service := range []string{"caddy", "frps", "headscale"} {
			name := h.name(service)
			var cs []struct {
				Config struct{ Labels map[string]string }
			}
			b, e := run(cleanup, nil, "inspect", name)
			if e != nil {
				continue
			}
			if json.Unmarshal(b, &cs) != nil || len(cs) != 1 || cs[0].Config.Labels[label] != h.ID {
				t.Error("fixture ownership mismatch")
				continue
			}
			if _, e = run(cleanup, nil, "rm", "-f", name); e != nil {
				t.Error(e)
			}
		}
		for _, part := range []string{"headscale-data", "headscale-config", "frps-config", "caddy-data", "caddy-config"} {
			if _, e := run(cleanup, nil, "volume", "rm", h.name(part)); e != nil {
				t.Log(e)
			}
		}
		if _, e := run(cleanup, nil, "network", "rm", h.name("network")); e != nil {
			t.Log(e)
		}
	})
	h.Docker.Run = func(ctx context.Context, input []byte, args ...string) ([]byte, error) {
		args = append([]string(nil), args...)
		if args[0] == "create" {
			if slicesContain(args, CaddyImage) {
				args = append([]string{"create", "--network-alias", h.Domain, "--add-host", "host.docker.internal:host-gateway"}, args[1:]...)
			}
			for i, arg := range args {
				if arg == "-p" {
					port := args[i+1][strings.LastIndex(args[i+1], ":")+1:]
					args[i+1] = "127.0.0.1::" + port
				}
			}
		}
		if args[0] == "cp" {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			tr := tar.NewReader(bytes.NewReader(input))
			for {
				header, e := tr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					return nil, e
				}
				data, e := io.ReadAll(tr)
				if e != nil {
					return nil, e
				}
				if header.Name == "etc/headscale/config.json" {
					var c map[string]any
					if e = json.Unmarshal(data, &c); e != nil {
						return nil, e
					}
					// Resolve the fixture Caddy alias instead of advertising a fake
					// public VPS address to clients inside this isolated bridge.
					delete(c["derp"].(map[string]any)["server"].(map[string]any), "ipv4")
					data = encoded(c)
					header.Size = int64(len(data))
				}
				if header.Name == "config/caddy.json" {
					var c map[string]any
					if e = json.Unmarshal(data, &c); e != nil {
						return nil, e
					}
					tls := c["apps"].(map[string]any)["tls"].(map[string]any)
					policies := tls["automation"].(map[string]any)["policies"].([]any)
					policies[0].(map[string]any)["issuers"] = []any{map[string]string{"module": "internal"}}
					if streamUpstream != "" {
						p := policies[0].(map[string]any)
						p["subjects"] = append(p["subjects"].([]any), "stream.deepai.test")
						edge := c["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["edge"].(map[string]any)
						edge["routes"] = append(edge["routes"].([]any), map[string]any{"match": []any{map[string]any{"host": []string{"stream.deepai.test"}}}, "handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]string{"dial": streamUpstream}}}}, "terminal": true})
					}
					data = encoded(c)
					header.Size = int64(len(data))
				}
				if e = tw.WriteHeader(header); e != nil {
					return nil, e
				}
				if _, e = tw.Write(data); e != nil {
					return nil, e
				}
			}
			if e := tw.Close(); e != nil {
				return nil, e
			}
			input = buf.Bytes()
		}
		return run(ctx, input, args...)
	}
	if err = h.save(); err != nil {
		t.Fatal(err)
	}
	if err = h.up(ctx); err != nil {
		for _, service := range []string{"headscale", "frps", "caddy"} {
			b, _ := run(ctx, nil, "logs", "--tail", "20", h.name(service))
			t.Log(service, string(b))
		}
		t.Fatal(err)
	}
	before := encoded(h.Containers)
	if err = h.up(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, encoded(h.Containers)) {
		t.Fatal("resume changed identity")
	}
	for _, service := range []string{"headscale", "frps", "caddy"} {
		if _, err = run(ctx, nil, "stop", h.Containers[service]); err != nil {
			t.Fatal(err)
		}
	}
	if err = h.up(ctx); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "authkey")
	if err = h.invite(ctx, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || len(b) < 32 {
		t.Fatal("enrollment credential missing")
	}
	if err = h.invite(ctx, out); err == nil {
		t.Fatal("overwrote enrollment credential")
	}
	if err = checkFresh(ctx, h.Docker); err == nil {
		t.Fatal("new deployment missed existing server resources")
	}
	ca := testMesh(t, ctx, h, run, out)
	testStandalonePublishing(t, ctx, h, run, ca)
	if streamUpstream != "" {
		testStreaming(t, ctx, h, run, ca)
	}
}

func slicesContain(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

func testMesh(t *testing.T, ctx context.Context, h *Server, run docker.Runner, authFile string) []byte {
	t.Helper()
	b, err := run(ctx, nil, "cp", h.Containers["caddy"]+":/data/caddy/pki/authorities/local/root.crt", "-")
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(b))
	if _, err = tr.Next(); err != nil {
		t.Fatal(err)
	}
	ca, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(suffix, keyPath string) meshPeer {
		name := h.name("test-peer-" + suffix)
		key, err := platform.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		id := createTestContainer(t, ctx, h, run, "peer-"+suffix, "--hostname", name,
			"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun:/dev/net/tun",
			"--env", "SSL_CERT_FILE=/etc/deepai-test-root.crt", "--entrypoint", "tailscaled",
			"tailscale/tailscale:v1.102.4", "--state=/var/lib/tailscale/tailscaled.state", "--socket=/var/run/tailscale/tailscaled.sock", "--port=41641")
		if err = h.Docker.CopyFiles(ctx, id, "/", map[string][]byte{"etc/deepai-test-root.crt": ca}); err != nil {
			t.Fatal(err)
		}
		if _, err = run(ctx, nil, "start", id); err != nil {
			t.Fatal(err)
		}
		pollFixture(t, ctx, func() bool {
			_, err := run(ctx, nil, "exec", id, "tailscale", "debug", "prefs")
			return err == nil
		})
		var credential bytes.Buffer
		tw := tar.NewWriter(&credential)
		key = bytes.TrimSpace(key)
		if err = tw.WriteHeader(&tar.Header{Name: "test-auth", Mode: 0600, Size: int64(len(key))}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(key); err != nil {
			t.Fatal(err)
		}
		if err = tw.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = run(ctx, credential.Bytes(), "exec", "-i", id, "tar", "-xf", "-", "-C", "/dev/shm"); err != nil {
			t.Fatal(err)
		}
		_, loginErr := run(ctx, nil, "exec", id, "tailscale", "up", "--accept-dns=false", "--hostname="+name,
			"--auth-key=file:/dev/shm/test-auth", "--timeout=45s", "--login-server=https://"+h.Domain)
		_, cleanupErr := run(ctx, nil, "exec", id, "rm", "-f", "/dev/shm/test-auth")
		if loginErr != nil {
			t.Fatal("mesh authentication failed", loginErr)
		}
		if cleanupErr != nil {
			t.Fatal("test key cleanup failed", cleanupErr)
		}
		var status struct {
			BackendState string
			TailscaleIPs []string
		}
		if err = h.Docker.JSON(ctx, &status, "exec", id, "tailscale", "status", "--json"); err != nil || status.BackendState != "Running" || len(status.TailscaleIPs) == 0 {
			t.Fatal("peer did not join the server mesh", err)
		}
		return meshPeer{ID: id, IP: status.TailscaleIPs[0]}
	}
	n1 := prepare("a", authFile)
	// Restarting a registered protocol client preserves the identity without a key.
	if _, err = run(ctx, nil, "restart", n1.ID); err != nil {
		t.Fatal(err)
	}
	pollFixture(t, ctx, func() bool {
		var status struct {
			BackendState string
			TailscaleIPs []string
		}
		return h.Docker.JSON(ctx, &status, "exec", n1.ID, "tailscale", "status", "--json") == nil && status.BackendState == "Running" && len(status.TailscaleIPs) > 0 && status.TailscaleIPs[0] == n1.IP
	})
	second := filepath.Join(h.Dir, "second-key")
	if err = h.invite(ctx, second); err != nil {
		t.Fatal(err)
	}
	n2 := prepare("b", second)
	if _, err = run(ctx, nil, "exec", n2.ID, "tailscale", "ping", "--timeout=10s", "--c=1", n1.IP); err != nil {
		t.Fatal("mesh peers could not connect", err)
	}
	for _, n := range []meshPeer{n1, n2} {
		if _, err = run(ctx, nil, "exec", n.ID, "iptables", "-I", "OUTPUT", "1", "-p", "udp", "!", "--dport", "53", "-j", "DROP"); err != nil {
			t.Fatal("could not block UDP in disposable mesh namespace", err)
		}
	}
	pong, err := run(ctx, nil, "exec", n2.ID, "tailscale", "ping", "--until-direct=false", "--timeout=20s", "--c=3", n1.IP)
	if err != nil || !bytes.Contains(pong, []byte("DERP(deepai)")) {
		t.Fatalf("owned DERP did not relay UDP-blocked peers: %s %v", pong, err)
	}
	t.Log("UDP-blocked peers connected through the owned DERP relay")
	var prefs struct{ ControlURL string }
	if err = h.Docker.JSON(ctx, &prefs, "exec", n2.ID, "tailscale", "debug", "prefs"); err != nil || prefs.ControlURL != "https://"+h.Domain {
		t.Fatal("wrong coordination server", err)
	}
	return ca
}

type meshPeer struct{ ID, IP string }

func pollFixture(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	timeout, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		if ready() {
			return
		}
		select {
		case <-timeout.Done():
			t.Fatal("fixture did not become ready", timeout.Err())
		case <-time.After(time.Second):
		}
	}
}

func testStreaming(t *testing.T, ctx context.Context, h *Server, run docker.Runner, ca []byte) {
	t.Helper()
	b, err := run(ctx, nil, "port", h.Containers["caddy"], "443/tcp")
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(string(b))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "stream.deepai.test", MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second}
	request, err := http.NewRequestWithContext(ctx, "POST", "https://stream.deepai.test/events", strings.NewReader("stream request"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 {
		t.Fatalf("expected HTTP/2 200, got %s %d", response.Proto, response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("after65s")) {
		t.Fatal("stream truncated before delayed event")
	}
	t.Log("HTTP/2 POST response streamed across a65-second idle interval")
}
