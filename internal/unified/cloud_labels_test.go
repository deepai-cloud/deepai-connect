package unified

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
)

type cloudLabelFixture struct {
	state        *coordinator.State
	registry     enrollment.Registry
	live         cloudLabelNode
	patches      []map[string]any
	nodeRequests int
	patchStatus  int
	nodeStatus   int
	beforePatch  func()
}

func newCloudLabelFixture() *cloudLabelFixture {
	f := &cloudLabelFixture{state: coordinator.NewState()}
	f.state.Nodes["machine-a"] = &coordinator.Node{MachineKey: "machine-a", Hostname: "worker-a", Role: "worker", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	f.registry = enrollment.Registry{
		Cluster: enrollment.Cluster{ID: "cloud-test"},
		Invites: map[string]*enrollment.Invite{},
		Members: map[string]*enrollment.Member{"machine-a": {Name: "worker-a", Role: "worker", Ready: true}},
		Cloud: &enrollment.DesiredCloud{
			Revision: "revision-1",
			Spec:     cloudconfig.Cloud{Nodes: map[string]cloudconfig.Node{"worker-a": {Role: "worker", Labels: map[string]string{"location": "home"}}}},
		},
	}
	f.live.Metadata.Name = "worker-a"
	f.live.Metadata.ResourceVersion = "17"
	f.live.Metadata.Labels = map[string]string{"connect.deepai.cloud/role": "worker", "connect.deepai.cloud/voter": "false", "owner": "local"}
	f.live.Metadata.Annotations = map[string]string{"unrelated": "preserve"}
	f.live.Status.Addresses = append(f.live.Status.Addresses, struct{ Type, Address string }{"InternalIP", "100.64.0.2"})
	f.live.Status.Conditions = append(f.live.Status.Conditions, struct{ Type, Status string }{"Ready", "True"})
	return f
}

func (f *cloudLabelFixture) kube(t *testing.T) kube {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/apis/connect.deepai.cloud/v1alpha1/namespaces/deepai-system/networkstates/default":
			if err := enrollment.WriteRegistry(f.state, f.registry); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": "9"}, "spec": f.state})
		case r.URL.Path == "/api/v1/nodes/worker-a":
			f.nodeRequests++
			if r.Method == http.MethodGet {
				if f.nodeStatus != 0 {
					w.WriteHeader(f.nodeStatus)
					return
				}
				_ = json.NewEncoder(w).Encode(f.live)
				return
			}
			if r.Method != http.MethodPatch {
				t.Errorf("unexpected node method %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("Content-Type") != "application/merge-patch+json" {
				t.Errorf("incorrect patch content type: %s", r.Header.Get("Content-Type"))
			}
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.patches = append(f.patches, patch)
			if f.beforePatch != nil {
				f.beforePatch()
			}
			if f.patchStatus != 0 {
				w.WriteHeader(f.patchStatus)
				return
			}
			meta := patch["metadata"].(map[string]any)
			if meta["resourceVersion"] != f.live.Metadata.ResourceVersion {
				w.WriteHeader(http.StatusConflict)
				return
			}
			for field, dest := range map[string]map[string]string{"labels": f.live.Metadata.Labels, "annotations": f.live.Metadata.Annotations} {
				if values, ok := meta[field].(map[string]any); ok {
					for key, value := range values {
						if value == nil {
							delete(dest, key)
						} else {
							dest[key] = value.(string)
						}
					}
				}
			}
			f.live.Metadata.ResourceVersion = "18"
			_ = json.NewEncoder(w).Encode(f.live)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(api.Close)
	return kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Namespace: "deepai-system", Client: api.Client()}}
}

func TestCloudLabelsOwnOnlyDeclaredLabelsAndReconcileIdempotently(t *testing.T) {
	f := newCloudLabelFixture()
	f.registry.Cloud.Spec.Nodes["worker-a"] = cloudconfig.Node{Role: "worker", Labels: map[string]string{"location": "home", "workload": "batch"}}
	f.live.Metadata.Labels["location"] = "office"
	f.live.Metadata.Labels["obsolete"] = "remove"
	f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = `["location","obsolete"]`
	k := f.kube(t)
	if err := reconcileCloudLabels(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 {
		t.Fatalf("got %d patches, want 1", len(f.patches))
	}
	metadata := f.patches[0]["metadata"].(map[string]any)
	wantLabels := map[string]any{"location": "home", "workload": "batch", "obsolete": nil}
	if !reflect.DeepEqual(metadata["labels"], wantLabels) || metadata["resourceVersion"] != "17" {
		t.Fatalf("unsafe or incomplete label patch: %#v", metadata)
	}
	if f.live.Metadata.Labels["owner"] != "local" || f.live.Metadata.Labels["connect.deepai.cloud/role"] != "worker" || f.live.Metadata.Annotations["unrelated"] != "preserve" {
		t.Fatal("reconciliation changed unrelated metadata")
	}
	if f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] != `["location","workload"]` {
		t.Fatalf("unexpected ownership: %s", f.live.Metadata.Annotations[cloudManagedLabelsAnnotation])
	}
	if err := reconcileCloudLabels(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 {
		t.Fatal("unchanged configuration issued another patch")
	}
}

func TestCloudLabelsReleaseOwnershipWhenLastLabelRemoved(t *testing.T) {
	f := newCloudLabelFixture()
	f.registry.Cloud.Spec.Nodes["worker-a"] = cloudconfig.Node{Role: "worker"}
	f.live.Metadata.Labels["location"] = "home"
	f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = `["location"]`
	if err := reconcileCloudLabels(context.Background(), f.kube(t)); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.live.Metadata.Labels["location"]; exists {
		t.Fatal("previously managed label survived removal")
	}
	if _, exists := f.live.Metadata.Annotations[cloudManagedLabelsAnnotation]; exists {
		t.Fatal("empty ownership annotation survived")
	}
	if f.live.Metadata.Labels["owner"] != "local" {
		t.Fatal("removed an unrelated label")
	}
}

func TestCloudLabelsRefuseUnmanagedConflictsAndUnsafeOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*cloudLabelFixture)
	}{
		{"unmanaged-conflict", func(f *cloudLabelFixture) { f.live.Metadata.Labels["location"] = "office" }},
		{"invalid-json", func(f *cloudLabelFixture) { f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = "invalid" }},
		{"null-ownership", func(f *cloudLabelFixture) { f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = "null" }},
		{"duplicate-ownership", func(f *cloudLabelFixture) {
			f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = `["location","location"]`
		}},
		{"forged-role-ownership", func(f *cloudLabelFixture) {
			f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = `["connect.deepai.cloud/role"]`
		}},
		{"forged-protected-ownership", func(f *cloudLabelFixture) {
			b, _ := json.Marshal([]string{cluster.ProtectedRoleLabel})
			f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = string(b)
		}},
		{"forged-kubernetes-ownership", func(f *cloudLabelFixture) {
			f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = `["node-role.kubernetes.io/control-plane"]`
		}},
		{"reserved-desired-label", func(f *cloudLabelFixture) {
			f.registry.Cloud.Spec.Nodes["worker-a"] = cloudconfig.Node{Role: "worker", Labels: map[string]string{"connect.deepai.cloud/role": "hub"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCloudLabelFixture()
			test.change(f)
			if err := reconcileCloudLabels(context.Background(), f.kube(t)); err == nil {
				t.Fatal("unsafe label reconciliation succeeded")
			}
			if len(f.patches) != 0 {
				t.Fatal("unsafe label reconciliation patched Kubernetes")
			}
		})
	}
}

func TestCloudLabelsVerifyEnrolledAndKubernetesIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*cloudLabelFixture)
	}{
		{"coordinator-name", func(f *cloudLabelFixture) { f.state.Nodes["machine-a"].Hostname = "other" }},
		{"coordinator-role", func(f *cloudLabelFixture) { f.state.Nodes["machine-a"].Role = "hub" }},
		{"coordinator-machine", func(f *cloudLabelFixture) { f.state.Nodes["machine-a"].MachineKey = "other" }},
		{"coordinator-missing", func(f *cloudLabelFixture) { delete(f.state.Nodes, "machine-a") }},
		{"declared-role", func(f *cloudLabelFixture) { f.registry.Cloud.Spec.Nodes["worker-a"] = cloudconfig.Node{Role: "hub"} }},
		{"kubernetes-name", func(f *cloudLabelFixture) { f.live.Metadata.Name = "other" }},
		{"kubernetes-role", func(f *cloudLabelFixture) { f.live.Metadata.Labels["connect.deepai.cloud/role"] = "hub" }},
		{"kubernetes-voter", func(f *cloudLabelFixture) { f.live.Metadata.Labels["connect.deepai.cloud/voter"] = "true" }},
		{"kubernetes-address", func(f *cloudLabelFixture) { f.live.Status.Addresses[0].Address = "100.64.0.9" }},
		{"kubernetes-not-ready", func(f *cloudLabelFixture) { f.live.Status.Conditions[0].Status = "False" }},
		{"kubernetes-missing-version", func(f *cloudLabelFixture) { f.live.Metadata.ResourceVersion = "" }},
		{"hub-lacks-protected-role", func(f *cloudLabelFixture) {
			f.registry.Cloud.Spec.Nodes["worker-a"] = cloudconfig.Node{Role: "hub", Labels: map[string]string{"location": "home"}}
			f.registry.Members["machine-a"].Role = "hub"
			f.state.Nodes["machine-a"].Role = "hub"
			f.live.Metadata.Labels["connect.deepai.cloud/role"] = "hub"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCloudLabelFixture()
			test.change(f)
			if err := reconcileCloudLabels(context.Background(), f.kube(t)); err == nil {
				t.Fatal("mismatched node identity was accepted")
			}
			if len(f.patches) != 0 {
				t.Fatal("patched a node without verifying its identity")
			}
		})
	}
}

func TestCloudLabelsSkipAbsentCloudAndInactiveMembers(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*cloudLabelFixture)
	}{
		{"no-cloud", func(f *cloudLabelFixture) { f.registry.Cloud = nil }},
		{"awaiting-enrollment", func(f *cloudLabelFixture) { f.registry.Members = map[string]*enrollment.Member{} }},
		{"incomplete-enrollment", func(f *cloudLabelFixture) { f.registry.Members["machine-a"].Ready = false }},
		{"revoked", func(f *cloudLabelFixture) { f.state.Nodes["machine-a"].Revoked = true }},
		{"undeclared", func(f *cloudLabelFixture) { f.registry.Cloud.Spec.Nodes = map[string]cloudconfig.Node{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCloudLabelFixture()
			test.change(f)
			if err := reconcileCloudLabels(context.Background(), f.kube(t)); err != nil {
				t.Fatal(err)
			}
			if f.nodeRequests != 0 {
				t.Fatal("accessed Kubernetes node that should be skipped")
			}
		})
	}
}

func TestCloudLabelsConflictLeavesStateUntouchedAndNextAttemptRetries(t *testing.T) {
	f := newCloudLabelFixture()
	f.patchStatus = http.StatusConflict
	k := f.kube(t)
	if err := reconcileCloudLabels(context.Background(), k); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("expected resourceVersion conflict, got %v", err)
	}
	if _, exists := f.live.Metadata.Labels["location"]; exists {
		t.Fatal("conflicting patch mutated node")
	}
	f.patchStatus = 0
	f.live.Metadata.ResourceVersion = "19"
	if err := reconcileCloudLabels(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 2 || f.patches[1]["metadata"].(map[string]any)["resourceVersion"] != "19" {
		t.Fatal("next attempt failed to read the current node version")
	}
}
