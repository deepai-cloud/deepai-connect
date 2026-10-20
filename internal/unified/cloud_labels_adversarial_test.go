package unified

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
)

func TestCloudLabelsApproveHubWithoutChangingItsSchedulingAuthority(t *testing.T) {
	f := newCloudLabelFixture()
	f.registry.Cloud.Spec.Nodes["worker-a"] = cloudconfig.Node{Role: "hub", Voter: true, Labels: map[string]string{"location": "home"}}
	f.registry.Members["machine-a"].Role = "hub"
	f.registry.Members["machine-a"].Voter = true
	f.state.Nodes["machine-a"].Role = "hub"
	f.live.Metadata.Labels["connect.deepai.cloud/role"] = "hub"
	f.live.Metadata.Labels["connect.deepai.cloud/voter"] = "true"
	f.live.Metadata.Labels[cluster.ProtectedRoleLabel] = "hub"
	if err := reconcileCloudLabels(context.Background(), f.kube(t)); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 {
		t.Fatalf("got %d patches, want one", len(f.patches))
	}
	labels := f.patches[0]["metadata"].(map[string]any)["labels"]
	if !reflect.DeepEqual(labels, map[string]any{"location": "home"}) {
		t.Fatalf("patch changed hub scheduling authority: %#v", labels)
	}
}

func TestCloudLabelsAdoptMatchingValueWithoutRewritingIt(t *testing.T) {
	f := newCloudLabelFixture()
	f.live.Metadata.Labels["location"] = "home"
	f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] = `["already-absent"]`
	k := f.kube(t)
	if err := reconcileCloudLabels(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 {
		t.Fatalf("got %d patches, want one ownership update", len(f.patches))
	}
	metadata := f.patches[0]["metadata"].(map[string]any)
	if _, rewrote := metadata["labels"]; rewrote {
		t.Fatalf("matching value or already-absent label was rewritten: %#v", metadata)
	}
	if f.live.Metadata.Annotations[cloudManagedLabelsAnnotation] != `["location"]` {
		t.Fatal("matching declared label was not adopted")
	}
	if err := reconcileCloudLabels(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 {
		t.Fatal("adoption did not converge")
	}
}

func TestCloudLabelsNodeReplacementBetweenReadAndPatchIsNotModified(t *testing.T) {
	f := newCloudLabelFixture()
	f.beforePatch = func() {
		// A replacement with the same name has a new resourceVersion and a
		// different overlay address. The stale write must fail its precondition.
		f.live.Metadata.ResourceVersion = "replacement-20"
		f.live.Status.Addresses[0].Address = "100.64.0.99"
	}
	k := f.kube(t)
	err := reconcileCloudLabels(context.Background(), k)
	if err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("replacement accepted stale patch: %v", err)
	}
	f.beforePatch = nil
	err = reconcileCloudLabels(context.Background(), k)
	if err == nil || !strings.Contains(err.Error(), "address or readiness differs") {
		t.Fatalf("retry failed to revalidate replacement identity: %v", err)
	}
	if len(f.patches) != 1 {
		t.Fatal("retry patched a same-name replacement")
	}
	if _, changed := f.live.Metadata.Labels["location"]; changed {
		t.Fatal("replacement inherited the previous member's labels")
	}
	if _, changed := f.live.Metadata.Annotations[cloudManagedLabelsAnnotation]; changed {
		t.Fatal("replacement inherited the previous member's ownership")
	}
}

func TestCloudLabelsFailedNodeReadNeverWritesAndRecovers(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newCloudLabelFixture()
			f.nodeStatus = status
			k := f.kube(t)
			if err := reconcileCloudLabels(context.Background(), k); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) {
				t.Fatalf("node read failure not reported: %v", err)
			}
			if len(f.patches) != 0 {
				t.Fatal("node read failure caused a patch")
			}
			f.nodeStatus = 0
			if err := reconcileCloudLabels(context.Background(), k); err != nil {
				t.Fatal(err)
			}
			if len(f.patches) != 1 || f.live.Metadata.Labels["location"] != "home" {
				t.Fatal("node did not reconcile after API recovery")
			}
		})
	}
}

func TestCloudLabelsFailureOnOneNodeDoesNotStarveOtherMembers(t *testing.T) {
	f := newCloudLabelFixture()
	f.registry.Members["machine-b"] = &enrollment.Member{Name: "worker-b", Role: "worker", Ready: true}
	f.registry.Cloud.Spec.Nodes["worker-b"] = cloudconfig.Node{Role: "worker", Labels: map[string]string{"location": "office"}}
	f.state.Nodes["machine-b"] = &coordinator.Node{MachineKey: "machine-b", Hostname: "worker-b", Role: "worker", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}}
	if err := enrollment.WriteRegistry(f.state, f.registry); err != nil {
		t.Fatal(err)
	}
	live := newCloudLabelFixture().live
	live.Metadata.Name = "worker-b"
	live.Status.Addresses[0].Address = "100.64.0.3"
	patched := make(chan map[string]any, 2)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/apis/connect.deepai.cloud/v1alpha1/namespaces/deepai-system/networkstates/default":
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": "9"}, "spec": f.state})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/nodes/worker-a":
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/nodes/worker-b":
			_ = json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/nodes/worker-b":
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			patched <- patch
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	k := kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Namespace: "deepai-system", Client: api.Client()}}
	err := reconcileCloudLabels(context.Background(), k)
	if err == nil || !strings.Contains(err.Error(), `node "worker-a"`) {
		t.Fatalf("failed member was not reported: %v", err)
	}
	select {
	case patch := <-patched:
		labels := patch["metadata"].(map[string]any)["labels"]
		if !reflect.DeepEqual(labels, map[string]any{"location": "office"}) {
			t.Fatalf("wrong labels applied to healthy member: %#v", labels)
		}
	default:
		t.Fatal("one unavailable member prevented another member from reconciling")
	}
}

func TestCloudLabelReconcilerCancellationStopsInflightRequest(t *testing.T) {
	f := newCloudLabelFixture()
	if err := enrollment.WriteRegistry(f.state, f.registry); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/connect.deepai.cloud/v1alpha1/namespaces/deepai-system/networkstates/default" {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": "9"}, "spec": f.state})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/nodes/worker-a" {
			close(started)
			<-r.Context().Done()
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	logs := make(chan string, 1)
	k := kube{store: &coordinator.KubernetesStore{BaseURL: api.URL, Namespace: "deepai-system", Client: api.Client()}}
	go func() {
		defer close(done)
		runCloudLabelReconciler(ctx, k, func(format string, args ...any) { logs <- fmt.Sprintf(format, args...) })
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("reconciler did not start immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconciler ignored cancellation during API call")
	}
	select {
	case entry := <-logs:
		t.Fatalf("normal shutdown logged a reconciliation failure: %s", entry)
	default:
	}
}
