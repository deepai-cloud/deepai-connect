package cluster

import (
	"reflect"
	"testing"
)

func TestCloudNodeLabelRBACOnlyAllowsCoordinatorNodePatches(t *testing.T) {
	for _, namespace := range []string{Namespace, "private-cloud"} {
		t.Run(namespace, func(t *testing.T) {
			testCloudNodeLabelRBAC(t, namespace)
		})
	}
}

func testCloudNodeLabelRBAC(t *testing.T, namespace string) {
	t.Helper()
	config := services()
	config.Namespace = namespace
	all := resources(t, config)
	role := all["ClusterRole/connect-cloud-node-labels"]
	wantRules := []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"nodes"}, "verbs": []any{"patch"}}}
	if !reflect.DeepEqual(role["rules"], wantRules) {
		t.Fatalf("unexpected node label permissions: %#v", role["rules"])
	}
	binding := all["ClusterRoleBinding/connect-cloud-node-labels"]
	wantRef := map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "connect-cloud-node-labels"}
	if !reflect.DeepEqual(binding["roleRef"], wantRef) {
		t.Fatalf("unexpected role binding: %#v", binding["roleRef"])
	}
	wantSubjects := []any{map[string]any{"kind": "ServiceAccount", "name": "connect-coordinator", "namespace": namespace}}
	if !reflect.DeepEqual(binding["subjects"], wantSubjects) {
		t.Fatalf("node patch permission is not restricted to the coordinator: %#v", binding["subjects"])
	}
	deployment := all["Deployment/connect-coordinator"]
	podSpec := deployment["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if podSpec["serviceAccountName"] != "connect-coordinator" {
		t.Fatal("coordinator pod cannot use its narrowly scoped node-label permission")
	}
}
