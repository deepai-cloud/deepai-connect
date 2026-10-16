package cluster

import (
	"context"
	"strings"
	"testing"
)

func TestBootstrapCanCommitStateBeforeWaitingForReadiness(t *testing.T) {
	f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "get --raw /apis/apps/v1/namespaces/kube-system/deployments/") {
			return []byte(`{"metadata":{"resourceVersion":"1"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"packaged"}},"template":{"spec":{}}}}`), nil
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
	if len(f.calls)-before != 5 {
		t.Fatal("must wait for DNS, ingress, coordinator, relay and gateway readiness")
	}
	for _, call := range f.calls[before:] {
		if !strings.Contains(strings.Join(call.args, " "), "rollout status") {
			t.Fatal("readiness stage unexpectedly mutated cluster state")
		}
	}
}
