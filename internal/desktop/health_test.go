package desktop

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

const healthyNodeFixture = `{"items":[{"metadata":{"name":"hub"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"worker"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`
const healthyPodFixture = `{"items":[{"metadata":{"name":"dns","namespace":"kube-system"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"coordinator","namespace":"deepai-system"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"completed-job","namespace":"kube-system"},"status":{"phase":"Succeeded"}},{"metadata":{"name":"unrelated","namespace":"app"},"status":{"phase":"Failed"}}]}`
const healthyControllerFixture = `{"items":[
{"kind":"Deployment","metadata":{"namespace":"deepai-system","name":"connect-coordinator","generation":1},"spec":{"replicas":1},"status":{"observedGeneration":1,"readyReplicas":1,"availableReplicas":1,"updatedReplicas":1}},
{"kind":"Deployment","metadata":{"namespace":"kube-system","name":"coredns","generation":1},"spec":{"replicas":1},"status":{"observedGeneration":1,"readyReplicas":1,"availableReplicas":1,"updatedReplicas":1}},
{"kind":"Deployment","metadata":{"namespace":"kube-system","name":"traefik","generation":1},"spec":{"replicas":1},"status":{"observedGeneration":1,"readyReplicas":1,"availableReplicas":1,"updatedReplicas":1}},
{"kind":"DaemonSet","metadata":{"namespace":"deepai-system","name":"connect-relay","generation":1},"status":{"observedGeneration":1,"desiredNumberScheduled":1,"numberReady":1,"numberAvailable":1,"updatedNumberScheduled":1}},
{"kind":"DaemonSet","metadata":{"namespace":"deepai-system","name":"connect-gateway","generation":1},"status":{"observedGeneration":1,"desiredNumberScheduled":1,"numberReady":1,"numberAvailable":1,"updatedNumberScheduled":1}}
]}`

func TestDoctorReportsHealthyAndUnhealthyCluster(t *testing.T) {
	for _, unhealthy := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "unhealthy"}[unhealthy], func(t *testing.T) {
			cfg := desktopTestConfig(t)
			cfg.VM = "worker"
			desktopMockRunner(t, func(_ context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
				cmd := args[len(args)-1]
				switch {
				case name == "multipass":
					io.WriteString(out, `{"info":{"worker":{"state":"Running"}}}`)
				case strings.Contains(cmd, "'inspect'"):
					io.WriteString(out, testInspection(time.Now()))
				case strings.Contains(cmd, "'systemctl'"):
					io.WriteString(out, "active\n")
				case strings.Contains(cmd, "'--raw=/readyz?verbose'"):
					io.WriteString(out, "[+]ping ok\nreadyz check passed\n")
				case strings.Contains(cmd, "'get' 'nodes'"):
					fixture := healthyNodeFixture
					if unhealthy {
						fixture = strings.ReplaceAll(fixture, `"True"`, `"False"`)
					}
					io.WriteString(out, fixture)
				case strings.Contains(cmd, "'get' 'pods'"):
					fixture := healthyPodFixture
					if unhealthy {
						fixture = strings.ReplaceAll(fixture, `"Running"`, `"Pending"`)
					}
					io.WriteString(out, fixture)
				case strings.Contains(cmd, "'get' 'deployments,daemonsets'"):
					io.WriteString(out, healthyControllerFixture)
				default:
					t.Fatalf("unexpected probe %s %v", name, args)
				}
				return nil
			})
			var out bytes.Buffer
			err := report(context.Background(), cfg, true, &out)
			if unhealthy {
				if err == nil || !strings.Contains(err.Error(), "2 health check(s) failed") || !strings.Contains(out.String(), "FAIL nodes") || !strings.Contains(out.String(), "FAIL system pods") {
					t.Fatalf("unhealthy cluster reported healthy: %s, %v", out.String(), err)
				}
			} else if err != nil || strings.Contains(out.String(), "FAIL") || !strings.Contains(out.String(), "PASS local VM worker") {
				t.Fatalf("healthy cluster failed: %s, %v", out.String(), err)
			}
		})
	}
}

func TestDoctorMissingExecutablesFailsWithoutPanic(t *testing.T) {
	cfg := desktopTestConfig(t)
	cfg.VM = "worker"
	desktopMockRunner(t, func(_ context.Context, name string, _ []string, _ io.Reader, _, _ io.Writer) error {
		return errors.New(name + " executable not found")
	})
	var out bytes.Buffer
	if err := report(context.Background(), cfg, true, &out); err == nil || !strings.Contains(out.String(), "install Multipass") || !strings.Contains(out.String(), "SSH") {
		t.Fatalf("missing prerequisites did not give useful failures: %s, %v", out.String(), err)
	}
}

func TestMeshRequiresReadyFreshUnexpiredState(t *testing.T) {
	now := time.Now()
	state, err := parseInspect([]byte(testInspection(now)))
	if err != nil || state.health(now) != nil {
		t.Fatalf("valid mesh rejected: %v", err)
	}
	for _, change := range []func(*inspectState){
		func(s *inspectState) { s.Ready = false },
		func(s *inspectState) { s.Phase = "network" },
		func(s *inspectState) { s.LastSync = now.Add(-3 * time.Minute) },
		func(s *inspectState) { s.Expires = now.Add(-time.Second) },
	} {
		broken := state
		change(&broken)
		if broken.health(now) == nil {
			t.Fatalf("unhealthy mesh accepted: %+v", broken)
		}
	}
	for _, input := range []string{"", "worker test: phase=ready address=100.96.0.2", "hub test: phase=ready address=100.96.0.1"} {
		if _, err := parseInspect([]byte(input)); err == nil {
			t.Fatalf("invalid inspection accepted: %q", input)
		}
	}
}

func TestSystemPodsRequireBothNamespacesAndReadyRunningPods(t *testing.T) {
	if _, err := healthyPods([]byte(healthyPodFixture)); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{`{"items":[]}`, `{"items":[{"metadata":{"namespace":"kube-system","name":"old"},"status":{"phase":"Succeeded"}}]}`, strings.ReplaceAll(healthyPodFixture, `"True"`, `"False"`)} {
		if _, err := healthyPods([]byte(fixture)); err == nil {
			t.Fatalf("unhealthy pods accepted: %s", fixture)
		}
	}
}

func TestNodePressureFailsReadiness(t *testing.T) {
	fixture := `{"items":[{"metadata":{"name":"worker"},"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"DiskPressure","status":"True"}]}}]}`
	if _, err := healthyNodes([]byte(fixture)); err == nil || !strings.Contains(err.Error(), "DiskPressure") {
		t.Fatalf("pressure ignored: %v", err)
	}
}

func TestSystemControllersRejectMissingScaledDownAndStaleWorkloads(t *testing.T) {
	if _, err := healthyControllers([]byte(healthyControllerFixture)); err != nil {
		t.Fatal(err)
	}
	for name, fixture := range map[string]string{
		"missing coordinator": strings.ReplaceAll(healthyControllerFixture, "connect-coordinator", "unrelated"),
		"missing CoreDNS":     strings.ReplaceAll(healthyControllerFixture, "coredns", "unrelated"),
		"scaled to zero":      strings.ReplaceAll(healthyControllerFixture, `"replicas":1`, `"replicas":0`),
		"no hubs scheduled":   strings.ReplaceAll(healthyControllerFixture, `"desiredNumberScheduled":1`, `"desiredNumberScheduled":0`),
		"pending rollout":     strings.ReplaceAll(healthyControllerFixture, `"updatedReplicas":1`, `"updatedReplicas":0`),
		"stale observation":   strings.ReplaceAll(healthyControllerFixture, `"observedGeneration":1`, `"observedGeneration":0`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := healthyControllers([]byte(fixture)); err == nil {
				t.Fatal("unhealthy controller accepted")
			}
		})
	}
}
