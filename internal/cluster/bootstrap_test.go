package cluster

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestBootstrapCanCommitStateBeforeWaitingForReadiness(t *testing.T) {
	f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "get --raw /apis/apps/v1/namespaces/kube-system/deployments/") {
			return []byte(`{"metadata":{"resourceVersion":"1"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"packaged"}},"template":{"spec":{}}}}`), nil
		}
		if slices.Contains(args, hubNodesPath) {
			return []byte(gatewayHubNodes), nil
		}
		if slices.Contains(args, traefikConfigPath) || slices.Contains(args, "helmchartconfig") {
			return []byte(gatewayChart), nil
		}
		if slices.Contains(args, "gateway") {
			return []byte(readyGateway), nil
		}
		return nil, nil
	}}
	m := newManager(t, config(t), f)
	c := services()
	if err := m.ReconcileServices(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) == 0 {
		t.Fatal("bootstrap did not install Kubernetes resources")
	}
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call.args, " "), "rollout status") {
			t.Fatal("bootstrap waited for readiness before caller could commit membership")
		}
	}
	before := len(f.calls)
	if err := m.WaitServicesReady(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(f.calls)-before != 7 {
		t.Fatal("must wait for DNS, Traefik, Gateway API, coordinator, relay and Caddy readiness")
	}
	for _, call := range f.calls[before:] {
		if !strings.Contains(strings.Join(call.args, " "), "rollout status") && !slices.Contains(call.args, "gateway") && !slices.Contains(call.args, "service/traefik") {
			t.Fatal("readiness stage unexpectedly mutated cluster state")
		}
	}
}
