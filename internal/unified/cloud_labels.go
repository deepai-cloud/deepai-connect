package unified

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
)

const cloudManagedLabelsAnnotation = "connect.deepai.cloud/managed-labels"

// runCloudLabelReconciler runs separately from coordinator initialization so
// unavailable workers and transient Kubernetes conflicts do not delay the mesh.
func runCloudLabelReconciler(ctx context.Context, k kube, logf func(string, ...any)) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := reconcileCloudLabels(attempt, k)
		cancel()
		if err != nil && ctx.Err() == nil && logf != nil {
			logf("cloud node labels: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func reconcileCloudLabels(ctx context.Context, k kube) error {
	state, err := k.store.Load(ctx)
	if err != nil {
		return err
	}
	// Existing installations without enrollment/cloud configuration have no
	// manifest-owned labels to reconcile.
	if len(state.Extensions[enrollment.Extension]) == 0 {
		return nil
	}
	registry, err := enrollment.ReadRegistry(state)
	if err != nil {
		return err
	}
	if registry.Cloud == nil {
		return nil
	}
	var failures []error
	for machine, member := range registry.Members {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		if member == nil || !member.Ready {
			continue
		}
		declared, exists := registry.Cloud.Spec.Nodes[member.Name]
		if !exists {
			continue
		}
		node := state.Nodes[machine]
		if node != nil && node.Revoked {
			continue
		}
		if node == nil || node.MachineKey != machine || node.Hostname != member.Name || node.Role != member.Role || declared.Role != member.Role || declared.Voter != member.Voter {
			failures = append(failures, fmt.Errorf("node %q: cloud and enrolled identities differ", member.Name))
			continue
		}
		if err := reconcileCloudNodeLabels(ctx, k, node, member.Voter, declared.Labels); err != nil {
			failures = append(failures, fmt.Errorf("node %q: %w", member.Name, err))
		}
	}
	return errors.Join(failures...)
}

type cloudLabelNode struct {
	Metadata struct {
		Name            string            `json:"name"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Status struct {
		Addresses  []struct{ Type, Address string } `json:"addresses"`
		Conditions []struct{ Type, Status string }  `json:"conditions"`
	} `json:"status"`
}

func reconcileCloudNodeLabels(ctx context.Context, k kube, enrolled *coordinator.Node, voter bool, desired map[string]string) error {
	if err := cloudconfig.ValidateLabels(desired); err != nil {
		return fmt.Errorf("invalid cloud labels: %w", err)
	}
	path := "/api/v1/nodes/" + url.PathEscape(enrolled.Hostname)
	var live cloudLabelNode
	if err := k.call(ctx, http.MethodGet, path, nil, &live); err != nil {
		return err
	}
	// Verify the identity using the same snapshot whose resourceVersion guards
	// the patch. A same-name replacement cannot receive this member's labels.
	if live.Metadata.Name != enrolled.Hostname || live.Metadata.ResourceVersion == "" ||
		live.Metadata.Labels["connect.deepai.cloud/role"] != enrolled.Role ||
		live.Metadata.Labels["connect.deepai.cloud/voter"] != fmt.Sprint(voter) {
		return errors.New("Kubernetes node identity or role differs from enrollment")
	}
	if enrolled.Role == "hub" && live.Metadata.Labels[cluster.ProtectedRoleLabel] != "hub" {
		return errors.New("Kubernetes hub lacks administrator-approved scheduling role")
	}
	address, ready := false, false
	for _, actual := range live.Status.Addresses {
		for _, expected := range enrolled.Addresses {
			if actual.Type == "InternalIP" && actual.Address == expected.Addr().String() {
				address = true
			}
		}
	}
	for _, condition := range live.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			ready = true
		}
	}
	if !address || !ready {
		return errors.New("Kubernetes node address or readiness differs from enrollment")
	}

	owned := make(map[string]string)
	previous, annotated := live.Metadata.Annotations[cloudManagedLabelsAnnotation]
	if annotated {
		var keys []string
		if err := json.Unmarshal([]byte(previous), &keys); err != nil || keys == nil {
			return errors.New("invalid managed-labels annotation")
		}
		for _, key := range keys {
			if _, duplicate := owned[key]; duplicate {
				return errors.New("duplicate managed label in ownership annotation")
			}
			owned[key] = ""
		}
		// Ownership metadata is not a source of authority for system labels.
		// In particular, a forged annotation must never remove hub approval.
		if err := cloudconfig.ValidateLabels(owned); err != nil {
			return fmt.Errorf("invalid managed-labels ownership: %w", err)
		}
	}

	labels := make(map[string]any)
	keys := make([]string, 0, len(desired))
	for key, value := range desired {
		_, managed := owned[key]
		current, exists := live.Metadata.Labels[key]
		if exists && current != value && !managed {
			return fmt.Errorf("label %q already has an unmanaged value", key)
		}
		if !exists || current != value {
			labels[key] = value
		}
		keys = append(keys, key)
	}
	for key := range owned {
		if _, desired := desired[key]; desired {
			continue
		}
		if _, exists := live.Metadata.Labels[key]; exists {
			labels[key] = nil
		}
	}
	slices.Sort(keys)
	encoded, _ := json.Marshal(keys)
	metadata := map[string]any{"resourceVersion": live.Metadata.ResourceVersion}
	if len(labels) > 0 {
		metadata["labels"] = labels
	}
	if len(keys) == 0 && annotated {
		metadata["annotations"] = map[string]any{cloudManagedLabelsAnnotation: nil}
	} else if len(keys) > 0 && previous != string(encoded) {
		metadata["annotations"] = map[string]any{cloudManagedLabelsAnnotation: string(encoded)}
	}
	if len(metadata) == 1 {
		return nil
	}
	return k.call(ctx, http.MethodPatch, path, map[string]any{"metadata": metadata}, nil)
}
