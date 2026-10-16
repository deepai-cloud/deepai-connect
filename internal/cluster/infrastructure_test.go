package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const packagedDeployment = `{"metadata":{"name":"coredns","resourceVersion":"7"},"spec":{"replicas":1,"selector":{"matchLabels":{"k8s-app":"kube-dns"}},"template":{"spec":{"nodeSelector":{"kubernetes.io/os":"linux","custom":"keep"},"serviceAccountName":"original-sa","containers":[{"name":"dns","image":"pinned:original","args":["original"]}],"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[]}},"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":10,"podAffinityTerm":{"topologyKey":"topology.kubernetes.io/zone","labelSelector":{"matchLabels":{"custom":"keep"}}}}]}}}}}}`

func TestInfrastructurePatchPreservesPackagedSettingsAndExistingPreferences(t *testing.T) {
	data, err := infrastructurePatch([]byte(packagedDeployment))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if p["metadata"].(map[string]any)["resourceVersion"] != "7" {
		t.Fatal("patch lacks CAS fence")
	}
	spec := p["spec"].(map[string]any)
	if spec["replicas"] != float64(2) {
		t.Fatal("singleton retained")
	}
	pod := spec["template"].(map[string]any)["spec"].(map[string]any)
	if !reflect.DeepEqual(pod["nodeSelector"], map[string]any{ProtectedRoleLabel: "hub"}) {
		t.Fatal("patch overwrites unrelated node selectors")
	}
	for _, key := range []string{"containers", "serviceAccountName", "volumes", "topologySpreadConstraints"} {
		if _, present := pod[key]; present {
			t.Fatalf("took ownership of packaged %s", key)
		}
	}
	affinity := pod["affinity"].(map[string]any)
	if _, present := affinity["nodeAffinity"]; present {
		t.Fatal("overwrote custom node affinity")
	}
	terms := affinity["podAntiAffinity"].(map[string]any)["preferredDuringSchedulingIgnoredDuringExecution"].([]any)
	if len(terms) != 2 || terms[0].(map[string]any)["weight"] != float64(10) {
		t.Fatal("existing spreading preference lost")
	}
	term := terms[1].(map[string]any)
	if term["weight"] != float64(100) || term["podAffinityTerm"].(map[string]any)["topologyKey"] != "kubernetes.io/hostname" {
		t.Fatal("hostname spreading missing")
	}
	// A healthy deployment with extra replicas should cause no write at all.
	var current map[string]any
	_ = json.Unmarshal([]byte(packagedDeployment), &current)
	currentSpec := current["spec"].(map[string]any)
	currentSpec["replicas"] = float64(4)
	currentPod := currentSpec["template"].(map[string]any)["spec"].(map[string]any)
	currentPod["nodeSelector"].(map[string]any)[ProtectedRoleLabel] = "hub"
	currentPod["affinity"].(map[string]any)["podAntiAffinity"] = affinity["podAntiAffinity"]
	encoded, _ := json.Marshal(current)
	if patch, err := infrastructurePatch(encoded); err != nil || patch != nil {
		t.Fatalf("unnecessary/destructive reconciliation: %s, %v", patch, err)
	}
}

func TestInfrastructureReconcilesPackagedResetAndBothDeployments(t *testing.T) {
	patches := map[string]int{}
	api := func(_ context.Context, method, path string, payload []byte) ([]byte, error) {
		if !strings.HasPrefix(path, "/apis/apps/v1/namespaces/kube-system/deployments/") {
			t.Fatalf("unexpected API %s", path)
		}
		if method == http.MethodGet {
			return []byte(packagedDeployment), nil
		}
		if method != http.MethodPatch || !strings.Contains(string(payload), `"resourceVersion":"7"`) {
			t.Fatal("unfenced/nonpatch mutation")
		}
		patches[path]++
		return nil, nil
	}
	// Models a K3s/chart reapply between background passes, including startup.
	for range 2 {
		if err := ReconcileInfrastructure(context.Background(), api); err != nil {
			t.Fatal(err)
		}
	}
	if len(patches) != 2 {
		t.Fatal("did not reconcile DNS and ingress")
	}
	for _, n := range patches {
		if n != 2 {
			t.Fatal("packaged reset was not repaired")
		}
	}
	err := ReconcileInfrastructure(context.Background(), func(ctx context.Context, method, path string, body []byte) ([]byte, error) {
		if strings.HasSuffix(path, "/coredns") {
			return nil, errors.New("HTTP 409")
		}
		return api(ctx, method, path, body)
	})
	if err == nil || patches["/apis/apps/v1/namespaces/kube-system/deployments/traefik"] != 3 {
		t.Fatal("one dependency error prevented repairing the other")
	}
}

func TestInfrastructureBackgroundCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		RunInfrastructureReconciler(ctx, func(ctx context.Context, _ string, _ string, _ []byte) ([]byte, error) { return nil, ctx.Err() }, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background reconciliation ignored shutdown")
	}
}

func TestInfrastructureRBACIsRestrictedToTwoDeployments(t *testing.T) {
	r := resources(t, services())["Role/connect-infrastructure-availability"]
	if r["metadata"].(map[string]any)["namespace"] != "kube-system" {
		t.Fatal("wrong infrastructure scope")
	}
	rules := r["rules"].([]any)
	if len(rules) != 1 {
		t.Fatal("unexpected broad permissions")
	}
	rule := rules[0].(map[string]any)
	if !reflect.DeepEqual(rule["resourceNames"], []any{"coredns", "traefik"}) || !reflect.DeepEqual(rule["verbs"], []any{"get", "patch"}) || !reflect.DeepEqual(rule["resources"], []any{"deployments"}) {
		t.Fatal("unbounded infrastructure permissions")
	}
}
