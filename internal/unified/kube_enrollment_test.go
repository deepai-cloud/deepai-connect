package unified

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
)

func TestEnrollmentBackendWorkerTokenIsScopedAndExpiring(t *testing.T) {
	dir := t.TempDir()
	serverToken := "K10" + strings.Repeat("a", 64) + "::server:full-admin"
	if err := os.WriteFile(filepath.Join(dir, "server-token"), []byte(serverToken), 0600); err != nil {
		t.Fatal(err)
	}
	var created map[string]any
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/v1/namespaces/kube-system/secrets" {
			t.Errorf("unexpected API %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			t.Error(err)
		}
		w.WriteHeader(201)
	}))
	defer api.Close()
	backend := clusterBackend{kube: kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Client: api.Client()}}, credentialsDir: dir}
	token, err := backend.Token(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if token == serverToken || !strings.HasPrefix(token, "K10"+strings.Repeat("a", 64)+"::") {
		t.Fatal("worker token exposes server credential or loses CA pin")
	}
	if created["type"] != "bootstrap.kubernetes.io/token" {
		t.Fatal("worker enrollment minted wrong Secret type")
	}
	data := created["stringData"].(map[string]any)
	if data["auth-extra-groups"] != "system:bootstrappers:k3s:default-node-token" {
		t.Fatal("worker received excessive bootstrap group")
	}
	expiry, err := time.Parse(time.RFC3339, data["expiration"].(string))
	if err != nil || time.Until(expiry) > 24*time.Hour || time.Until(expiry) < 23*time.Hour {
		t.Fatal("worker token not bounded to 24 hours")
	}
	if !strings.HasSuffix(token, data["token-id"].(string)+"."+data["token-secret"].(string)) {
		t.Fatal("returned credential differs from persisted token")
	}
	hubToken, err := backend.Token(context.Background(), true)
	if err != nil || hubToken != serverToken || calls != 1 {
		t.Fatal("hub enrollment unexpectedly changed server credentials")
	}
}
func TestEnrollmentBackendVerifiesKubernetesIdentityBeforeCompletion(t *testing.T) {
	node := coordinator.Node{Hostname: "joining-hub", Role: "hub", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}}
	for _, test := range []struct {
		name, role, voter, ip, status string
		want                          bool
	}{{"valid", "hub", "true", "100.64.0.9", "True", true}, {"wrong-address", "hub", "true", "192.0.2.1", "True", false}, {"wrong-role", "worker", "true", "100.64.0.9", "True", false}, {"wrong-vote", "hub", "false", "100.64.0.9", "True", false}, {"not-ready", "hub", "true", "100.64.0.9", "False", false}} {
		t.Run(test.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"labels": map[string]string{"connect.deepai.cloud/role": test.role, "connect.deepai.cloud/voter": test.voter, cluster.ProtectedRoleLabel: "hub"}}, "status": map[string]any{"addresses": []any{map[string]string{"type": "InternalIP", "address": test.ip}}, "conditions": []any{map[string]string{"type": "Ready", "status": test.status}}}})
			}))
			defer api.Close()
			backend := clusterBackend{kube: kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Client: api.Client()}}}
			err := backend.ValidateNode(context.Background(), node, true, true)
			if (err == nil) != test.want {
				t.Fatalf("verification got %v want success=%v", err, test.want)
			}
			if err = backend.ValidateNode(context.Background(), node, true, false); err == nil {
				t.Fatal("fresh enrollment adopted an existing Kubernetes node")
			}
		})
	}
}

func TestHubCompletionRequiresAdministratorSchedulingApproval(t *testing.T) {
	for _, test := range []struct {
		name, role, protectedRole string
		want                      bool
	}{
		{"self-asserted-hub", "hub", "", false},
		{"wrong-protected-role", "hub", "worker", false},
		{"approved-hub", "hub", "hub", true},
		{"ordinary-worker", "worker", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				labels := map[string]string{"connect.deepai.cloud/role": test.role, "connect.deepai.cloud/voter": "false"}
				if test.protectedRole != "" {
					labels[cluster.ProtectedRoleLabel] = test.protectedRole
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"labels": labels}, "status": map[string]any{"addresses": []any{map[string]string{"type": "InternalIP", "address": "100.64.0.9"}}, "conditions": []any{map[string]string{"type": "Ready", "status": "True"}}}})
			}))
			defer api.Close()
			backend := clusterBackend{kube: kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Client: api.Client()}}}
			node := coordinator.Node{Hostname: "joining-node", Role: test.role, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}}
			if err := backend.ValidateNode(context.Background(), node, false, true); (err == nil) != test.want {
				t.Fatalf("hub scheduling authorization: got %v, want success=%v", err, test.want)
			}
		})
	}
}
func TestEnrollmentBackendFreshNameFailsClosedOnAPIError(t *testing.T) {
	for _, status := range []int{404, 403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer api.Close()
			backend := clusterBackend{kube: kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Client: api.Client()}}}
			err := backend.ValidateNode(context.Background(), coordinator.Node{Hostname: "candidate"}, false, false)
			if (err == nil) != (status == 404) {
				t.Fatalf("status %d returned %v", status, err)
			}
		})
	}
}
