package connect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"github.com/deepai-cloud/deepai-connect/internal/runtime/docker"
)

func testStandalonePublishing(t *testing.T, ctx context.Context, h *Server, run docker.Runner, ca []byte) {
	t.Helper()
	marker := "standalone publishing " + h.ID + "\n"
	backend := createTestContainer(t, ctx, h, run, "backend", CaddyImage, "caddy", "file-server", "--listen", ":8080", "--root", "/srv")
	if err := h.Docker.CopyFiles(ctx, backend, "/", map[string][]byte{"srv/index.html": []byte(marker)}); err != nil {
		t.Fatal(err)
	}
	if _, err := run(ctx, nil, "start", backend); err != nil {
		t.Fatal(err)
	}
	ip := func(id string) string {
		t.Helper()
		b, err := run(ctx, nil, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", id)
		address := strings.TrimSpace(string(b))
		if err != nil || net.ParseIP(address) == nil {
			t.Fatal("fixture container has no bridge address", err)
		}
		return address
	}
	backendIP, serverIP := ip(backend), ip(h.Containers["frps"])
	b, err := run(ctx, nil, "port", h.Containers["caddy"], "443/tcp")
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(string(b))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture HTTPS root is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: h.Apps[0], MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response := func(host string) (int, string, error) {
		request, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
		if err != nil {
			return 0, "", err
		}
		resp, err := client.Do(request)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, string(body), err
	}
	for _, scenario := range []string{"bad-token", "bad-ca", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "publisher")
			if err := Run(ctx, []string{"access", "--dir", h.Dir, "--format", "frpc", "--domain", h.Apps[0], "--local-ip", backendIP, "--local-port", "8080", "--out", bundle}); err != nil {
				t.Fatal("server could not export a standalone FRPC bundle", err)
			}
			switch scenario {
			case "bad-token":
				err = platform.WriteFile(filepath.Join(bundle, "token"), []byte(strings.Repeat("0", 64)), false)
			case "bad-ca":
				err = platform.WriteFile(filepath.Join(bundle, "ca.pem"), ca, false) // Valid but unrelated CA.
			}
			if err != nil {
				t.Fatal(err)
			}
			// Resolve the public hostname to FRPS on this private bridge. The
			// exported configuration and relative secret paths remain unchanged.
			id := createTestContainer(t, ctx, h, run, scenario, "--add-host", h.Domain+":"+serverIP,
				"--mount", "type=bind,src="+bundle+",dst=/bundle,readonly", "--workdir", "/bundle",
				"ghcr.io/fatedier/frpc:v0.71.0", "-c", "frpc.json")
			if _, err := run(ctx, nil, "start", id); err != nil {
				t.Fatal(err)
			}
			if scenario != "valid" {
				var containers []struct {
					State struct {
						Running  bool
						ExitCode int
					}
				}
				pollFixture(t, ctx, func() bool {
					return h.Docker.JSON(ctx, &containers, "inspect", id) == nil && len(containers) == 1 && !containers[0].State.Running
				})
				if containers[0].State.ExitCode == 0 {
					t.Fatal("FRPC accepted invalid publishing credentials")
				}
				if _, body, err := response(h.Apps[0]); err != nil || body == marker {
					t.Fatal("invalid publisher was not rejected by the live HTTPS edge", err)
				}
				return
			}
			pollFixture(t, ctx, func() bool {
				status, body, err := response(h.Apps[0])
				return err == nil && status == http.StatusOK && body == marker
			})
			if _, body, err := response("unconfigured.deepai.test"); err != nil || body == marker {
				t.Fatal("HTTPS edge served an unconfigured application hostname", err)
			}
			t.Log("Caddy HTTPS → FRPS TLS → unmodified FRPC bundle → HTTP backend passed")
		})
	}
}

func createTestContainer(t *testing.T, ctx context.Context, h *Server, run docker.Runner, suffix string, args ...string) string {
	t.Helper()
	name := h.name("test-" + suffix)
	args = append([]string{"create", "--name", name, "--label", label + ".test=" + h.ID, "--network", h.name("network")}, args...)
	b, err := run(ctx, nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(b))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := h.Docker.Inspect(cleanup, name)
		if err != nil || c == nil || c.ID != id || c.Config.Labels[label+".test"] != h.ID {
			t.Error("test container ownership cannot be verified", err)
			return
		}
		if _, err := run(cleanup, nil, "rm", "-f", id); err != nil {
			t.Error(err)
		}
	})
	return id
}
