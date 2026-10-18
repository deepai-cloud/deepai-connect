package unified

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
)

func TestKubernetesClientsReuseConnections(t *testing.T) {
	for _, clientName := range []string{"enrollment", "infrastructure"} {
		for _, status := range []int{http.StatusOK, http.StatusConflict} {
			t.Run(clientName+"/"+http.StatusText(status), func(t *testing.T) {
				var connections atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(status)
					if status == http.StatusOK {
						// Decoding the object alone need not consume the full body.
						_, _ = io.WriteString(w, `{"ready":true}`+strings.Repeat(" ", 8192))
					} else {
						_, _ = io.WriteString(w, strings.Repeat("private-conflict-details", 400))
					}
				}))
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				server.StartTLS()
				defer server.Close()
				store := &coordinator.KubernetesStore{BaseURL: server.URL, Client: server.Client()}
				for range 5 {
					var err error
					if clientName == "enrollment" {
						var out map[string]any
						err = (kube{store}).call(context.Background(), http.MethodGet, "/", nil, &out)
					} else {
						_, err = (kube{store}).infrastructure(context.Background(), http.MethodGet, "/", nil)
					}
					if (err == nil) != (status == http.StatusOK) {
						t.Fatalf("status %d: %v", status, err)
					}
					if err != nil && strings.Contains(err.Error(), "private-conflict-details") {
						t.Fatal("Kubernetes error exposed the response body")
					}
				}
				if got := connections.Load(); got != 1 {
					t.Fatalf("five requests established %d TLS connections; want one", got)
				}
			})
		}
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type oversizedKubernetesBody struct {
	read   int
	closed bool
}

func (b *oversizedKubernetesBody) Read(p []byte) (int, error) {
	clear(p)
	b.read += len(p)
	return len(p), nil
}
func (b *oversizedKubernetesBody) Close() error { b.closed = true; return nil }

func TestKubernetesErrorDrainIsBounded(t *testing.T) {
	for _, clientName := range []string{"enrollment", "infrastructure"} {
		t.Run(clientName, func(t *testing.T) {
			body := &oversizedKubernetesBody{}
			store := &coordinator.KubernetesStore{BaseURL: "https://kubernetes.invalid", Client: &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusForbidden, Body: body, Header: make(http.Header)}, nil
			})}}
			var err error
			if clientName == "enrollment" {
				err = (kube{store}).call(context.Background(), http.MethodGet, "/", nil, nil)
			} else {
				_, err = (kube{store}).infrastructure(context.Background(), http.MethodGet, "/", nil)
			}
			if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
				t.Fatalf("authorization error lost: %v", err)
			}
			if !body.closed || body.read > 64<<10 {
				t.Fatalf("unbounded or unclosed body: read=%d, closed=%v", body.read, body.closed)
			}
		})
	}
}
