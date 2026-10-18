package unified

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
)

func TestInfrastructureAPIUsesMergePatchAndRereadsProjectedToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/apps/v1/namespaces/kube-system/deployments/coredns" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Method == http.MethodGet {
			if r.Header.Get("Authorization") != "Bearer first" {
				t.Error("GET token")
			}
			if err := os.WriteFile(file, []byte("rotated\n"), 0600); err != nil {
				t.Error(err)
			}
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"7"}}`)
			return
		}
		if r.Method != http.MethodPatch || r.Header.Get("Content-Type") != "application/merge-patch+json" || r.Header.Get("Authorization") != "Bearer rotated" {
			t.Error("PATCH method/content type/rotated token")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"metadata":{"resourceVersion":"7"},"spec":{"replicas":2}}` {
			t.Errorf("payload %s", body)
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	api := kube{&coordinator.KubernetesStore{BaseURL: server.URL, TokenFile: file, Client: server.Client()}}.infrastructure
	path := "/apis/apps/v1/namespaces/kube-system/deployments/coredns"
	if _, err := api(context.Background(), http.MethodGet, path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := api(context.Background(), http.MethodPatch, path, []byte(`{"metadata":{"resourceVersion":"7"},"spec":{"replicas":2}}`)); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("conflict lost: %v", err)
	}
}
