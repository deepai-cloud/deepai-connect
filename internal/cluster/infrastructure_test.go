package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const packagedDeployment = `{"metadata":{"name":"coredns","resourceVersion":"7"},"spec":{"replicas":1,"selector":{"matchLabels":{"k8s-app":"kube-dns"}},"template":{"spec":{"nodeSelector":{"kubernetes.io/os":"linux","custom":"keep"},"serviceAccountName":"original-sa","containers":[{"name":"dns","image":"pinned:original","args":["original"]}],"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[]}},"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":10,"podAffinityTerm":{"topologyKey":"topology.kubernetes.io/zone","labelSelector":{"matchLabels":{"custom":"keep"}}}}]}}}}}}`

func BenchmarkInfrastructurePatch(b *testing.B) {
	var deployment map[string]any
	if err := json.Unmarshal([]byte(packagedDeployment), &deployment); err != nil {
		b.Fatal(err)
	}
	// Kubernetes returns managed fields and the entire pod template even though
	// reconciliation only needs the availability policy. Model a Helm-managed
	// deployment with field ownership and container configuration.
	fields := make(map[string]any, 200)
	env := make([]any, 200)
	for i := range env {
		name := fmt.Sprintf("SETTING_%03d", i)
		fields["f:"+name] = map[string]any{".": map[string]any{}, "f:value": map[string]any{}}
		env[i] = map[string]string{"name": name, "value": strings.Repeat("value", 20)}
	}
	deployment["metadata"].(map[string]any)["managedFields"] = []any{map[string]any{"manager": "helm", "fieldsType": "FieldsV1", "fieldsV1": fields}}
	pod := deployment["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	pod["containers"].([]any)[0].(map[string]any)["env"] = env
	data, err := json.Marshal(deployment)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := infrastructurePatch(data); err != nil {
			b.Fatal(err)
		}
	}
}

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

func TestInfrastructurePatchPreservesUnrecognizedAffinityFields(t *testing.T) {
	var deployment map[string]any
	if err := json.Unmarshal([]byte(packagedDeployment), &deployment); err != nil {
		t.Fatal(err)
	}
	spec := deployment["spec"].(map[string]any)
	selector := spec["selector"].(map[string]any)
	selector["matchExpressions"] = []any{map[string]any{"key": "custom", "operator": "Exists"}}
	pod := spec["template"].(map[string]any)["spec"].(map[string]any)
	preferred := pod["affinity"].(map[string]any)["podAntiAffinity"].(map[string]any)["preferredDuringSchedulingIgnoredDuringExecution"].([]any)
	term := preferred[0].(map[string]any)["podAffinityTerm"].(map[string]any)
	term["namespaces"] = []any{"custom-system"}
	term["matchLabelKeys"] = []any{"pod-template-hash"}
	term["futureField"] = map[string]any{"nested": []any{true, "keep"}}
	data, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := infrastructurePatch(data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(patch, &decoded); err != nil {
		t.Fatal(err)
	}
	patchedPod := decoded["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	patchedTerms := patchedPod["affinity"].(map[string]any)["podAntiAffinity"].(map[string]any)["preferredDuringSchedulingIgnoredDuringExecution"].([]any)
	if len(patchedTerms) != 2 || !reflect.DeepEqual(patchedTerms[0], preferred[0]) {
		t.Fatal("reconciliation dropped fields from an existing affinity preference")
	}
	if got := patchedTerms[1].(map[string]any)["podAffinityTerm"].(map[string]any)["labelSelector"]; !reflect.DeepEqual(got, selector) {
		t.Fatal("spreading preference dropped selector expressions")
	}
}

func TestInfrastructurePatchRejectsMalformedOwnedFields(t *testing.T) {
	for _, data := range []string{
		`{"metadata":{"resourceVersion":7},"spec":{"selector":{"matchLabels":{}}}}`,
		`{"metadata":{"resourceVersion":"7"},"spec":{"replicas":"2","selector":{"matchLabels":{}}}}`,
		`{"metadata":{"resourceVersion":"7"},"spec":{"replicas":1.5,"selector":{"matchLabels":{}}}}`,
		`{"metadata":{"resourceVersion":"7"},"spec":{"selector":[]}}`,
		`{"metadata":{"resourceVersion":"7"},"spec":{"selector":{"matchLabels":{}},"template":{"spec":{"nodeSelector":{"custom":42}}}}}`,
		`{"metadata":{"resourceVersion":"7"},"spec":{"selector":{"matchLabels":{}},"template":{"spec":{"affinity":[]}}}}`,
		`{"metadata":{"resourceVersion":"7"},"spec":{"selector":{"matchLabels":{}},"template":{"spec":{"affinity":{"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":{}}}}}}}`,
	} {
		if patch, err := infrastructurePatch([]byte(data)); err == nil || patch != nil {
			t.Fatalf("malformed owned fields produced a repair: %s, %v", patch, err)
		}
	}
}

func TestInfrastructureReconcilesPackagedResetAndBothDeployments(t *testing.T) {
	patches := map[string]int{}
	api := func(_ context.Context, method, path string, payload []byte) ([]byte, error) {
		if path == hubNodesPath {
			return []byte(gatewayHubNodes), nil
		}
		if path == traefikConfigPath {
			if method == http.MethodGet {
				return []byte(gatewayChart), nil
			}
			return nil, nil
		}
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

func TestInfrastructureRBACIsRestrictedToPackagedResources(t *testing.T) {
	r := resources(t, services())["Role/connect-infrastructure-availability"]
	if r["metadata"].(map[string]any)["namespace"] != "kube-system" {
		t.Fatal("wrong infrastructure scope")
	}
	rules := r["rules"].([]any)
	if len(rules) != 2 {
		t.Fatal("unexpected broad permissions")
	}
	rule := rules[0].(map[string]any)
	if !reflect.DeepEqual(rule["resourceNames"], []any{"coredns", "traefik"}) || !reflect.DeepEqual(rule["verbs"], []any{"get", "patch"}) || !reflect.DeepEqual(rule["resources"], []any{"deployments"}) {
		t.Fatal("unbounded infrastructure permissions")
	}
	rule = rules[1].(map[string]any)
	if !reflect.DeepEqual(rule["resourceNames"], []any{"traefik"}) || !reflect.DeepEqual(rule["verbs"], []any{"get", "patch"}) || !reflect.DeepEqual(rule["resources"], []any{"helmchartconfigs"}) {
		t.Fatal("unbounded chart permissions")
	}
}
