package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// InfrastructureAPI shares the caller's authenticated Kubernetes connection.
// Only the two packaged Deployments below are read or patched.
type InfrastructureAPI func(context.Context, string, string, []byte) ([]byte, error)

var infrastructureDeployments = []string{"coredns", "traefik"}

func infrastructurePatch(data []byte) ([]byte, error) {
	var deployment map[string]any
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, err
	}
	meta, _ := deployment["metadata"].(map[string]any)
	version, _ := meta["resourceVersion"].(string)
	spec, _ := deployment["spec"].(map[string]any)
	selector, _ := spec["selector"].(map[string]any)
	if version == "" || len(selector) == 0 {
		return nil, errors.New("packaged deployment lacks resourceVersion or pod selector")
	}
	template, _ := spec["template"].(map[string]any)
	pod, _ := template["spec"].(map[string]any)
	nodes, _ := pod["nodeSelector"].(map[string]any)
	affinity, _ := pod["affinity"].(map[string]any)
	anti, _ := affinity["podAntiAffinity"].(map[string]any)
	preferred, _ := anti["preferredDuringSchedulingIgnoredDuringExecution"].([]any)
	term := resource{"weight": 100, "podAffinityTerm": resource{"topologyKey": "kubernetes.io/hostname", "labelSelector": selector}}
	want, _ := json.Marshal(term)
	hasTerm := false
	for _, existing := range preferred {
		got, _ := json.Marshal(existing)
		if bytes.Equal(got, want) {
			hasTerm = true
		}
	}
	patchSpec := resource{}
	if replicas, _ := spec["replicas"].(float64); replicas < 2 {
		patchSpec["replicas"] = 2
	}
	patchPod := resource{}
	if nodes[ProtectedRoleLabel] != "hub" {
		patchPod["nodeSelector"] = resource{ProtectedRoleLabel: "hub"}
	}
	if !hasTerm {
		// Merge patch preserves unrelated affinity fields; the resourceVersion
		// fence protects this append from concurrent administrator changes.
		patchPod["affinity"] = resource{"podAntiAffinity": resource{"preferredDuringSchedulingIgnoredDuringExecution": append(preferred, term)}}
	}
	if len(patchPod) > 0 {
		patchSpec["template"] = resource{"spec": patchPod}
	}
	if len(patchSpec) == 0 {
		return nil, nil
	}
	return json.Marshal(resource{"metadata": resource{"resourceVersion": version}, "spec": patchSpec})
}

// ReconcileInfrastructure preserves packaged images, configuration, Services,
// service accounts and other pod settings. K3s and Helm may reapply their
// packaged manifests on restart or upgrade; RunInfrastructureReconciler repairs
// the narrow availability policy afterward without taking over those packages.
func ReconcileInfrastructure(ctx context.Context, api InfrastructureAPI) error {
	var result error
	for _, name := range infrastructureDeployments {
		path := "/apis/apps/v1/namespaces/kube-system/deployments/" + name
		data, err := api(ctx, http.MethodGet, path, nil)
		if err == nil {
			var patch []byte
			patch, err = infrastructurePatch(data)
			if err == nil && patch != nil {
				_, err = api(ctx, http.MethodPatch, path, patch)
			}
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%s availability: %w", name, err))
		}
	}
	return result
}

// RunInfrastructureReconciler does not gate coordinator availability on a
// temporary package/API error. Its authenticated API endpoint is an IP, so
// repairing DNS does not itself require DNS.
func RunInfrastructureReconciler(ctx context.Context, api InfrastructureAPI, logf func(string, ...any)) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := ReconcileInfrastructure(attempt, api)
		cancel()
		if err != nil && ctx.Err() == nil && logf != nil {
			logf("Kubernetes infrastructure reconciliation: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) reconcileInfrastructure(ctx context.Context) error {
	api := func(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
		if method == http.MethodGet {
			return m.Kubectl(ctx, nil, "get", "--raw", path)
		}
		name := path[len("/apis/apps/v1/namespaces/kube-system/deployments/"):]
		return m.Kubectl(ctx, nil, "-n", "kube-system", "patch", "deployment", name, "--type=merge", "-p", string(payload))
	}
	wait, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	for {
		err := ReconcileInfrastructure(wait, api)
		if err == nil {
			return nil
		}
		select {
		case <-wait.Done():
			return fmt.Errorf("waiting for packaged DNS and ingress: %w", err)
		case <-time.After(2 * time.Second):
		}
	}
}
