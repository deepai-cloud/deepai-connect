package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const gatewayHubNodes = `{"items":[{"metadata":{"labels":{"connect.deepai.cloud.node-restriction.kubernetes.io/role":"hub"}},"spec":{"podCIDR":"10.42.2.0/24","podCIDRs":["10.42.2.0/24","fd00:42:2::/64"]},"status":{"addresses":[{"type":"InternalIP","address":"100.96.0.7"}]}},{"metadata":{"labels":{"role":"hub"}},"spec":{"podCIDR":"10.42.3.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"100.96.0.8"}]}}]}`
const gatewayChart = `{"metadata":{"resourceVersion":"8"},"spec":{"valuesContent":"{}"}}`
const readyGateway = `{"metadata":{"generation":1},"status":{"conditions":[{"type":"Accepted","status":"True","observedGeneration":1},{"type":"Programmed","status":"True","observedGeneration":1}]}}`

func TestGatewayTrustUsesOnlyProtectedHubAddresses(t *testing.T) {
	ips, err := trustedHubProxies([]byte(gatewayHubNodes))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ips, []string{"10.42.2.1/32", "100.96.0.7/32", "fd00:42:2::1/128"}) {
		t.Fatalf("proxy trust too broad: %v", ips)
	}
	if empty, err := trustedHubProxies([]byte(`{"items":[]}`)); err != nil || len(empty) != 0 {
		t.Fatal("last hub removal must revoke all proxy trust")
	}
	for _, data := range []string{`{}`, strings.ReplaceAll(gatewayHubNodes, "10.42.2.0/24", "10.42.2.3/24"), strings.ReplaceAll(gatewayHubNodes, "100.96.0.7", "invalid")} {
		if _, err := trustedHubProxies([]byte(data)); err == nil {
			t.Fatal("accepted malformed proxy addresses")
		}
	}
}

func TestTraefikValuesPreserveCustomSettingsAndRevokeTrust(t *testing.T) {
	original := "deployment:\n  replicas: 4\nimage:\n  tag: custom\nnodeSelector:\n  custom: keep\nports:\n  web:\n    forwardedHeaders:\n      insecure: true\n      trustedIPs: [0.0.0.0/0]\n    transport:\n      lifeCycle:\n        graceTimeOut: 20s\n"
	value, changed, err := traefikValues(original, []byte(gatewayHubNodes))
	if err != nil || !changed {
		t.Fatalf("%v, %t", err, changed)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(value), &v); err != nil {
		t.Fatal(err)
	}
	if v["deployment"].(map[string]any)["replicas"] != float64(4) || v["image"].(map[string]any)["tag"] != "custom" || v["nodeSelector"].(map[string]any)["custom"] != "keep" {
		t.Fatal("discarded custom chart settings")
	}
	service := v["service"].(map[string]any)
	if service["spec"].(map[string]any)["type"] != "ClusterIP" || service["type"] != nil {
		t.Fatal("Service type must use the pinned chart v40 schema")
	}
	web := v["ports"].(map[string]any)["web"].(map[string]any)
	if web["transport"] == nil || web["forwardedHeaders"].(map[string]any)["insecure"] != false || strings.Contains(value, "0.0.0.0/0") {
		t.Fatal("unsafe trust or lost transport")
	}
	if _, changed, err := traefikValues(value, []byte(gatewayHubNodes)); err != nil || changed {
		t.Fatalf("not idempotent: %v", err)
	}
	next := strings.ReplaceAll(gatewayHubNodes, "100.96.0.7", "100.96.0.9")
	value, changed, err = traefikValues(value, []byte(next))
	if err != nil || !changed || strings.Contains(value, "100.96.0.7") || !strings.Contains(value, "100.96.0.9/32") {
		t.Fatal("stale hub trust retained")
	}
	if _, _, err := traefikValues("ports: disabled", []byte(gatewayHubNodes)); err == nil {
		t.Fatal("overwrote incompatible operator setting")
	}
}

func TestGatewayChartUpdateIsVersionFencedAndNarrow(t *testing.T) {
	err := reconcileGatewayChart(context.Background(), func(_ context.Context, method, path string, body []byte) ([]byte, error) {
		if path == hubNodesPath && method == http.MethodGet {
			return []byte(gatewayHubNodes), nil
		}
		if path != traefikConfigPath {
			t.Fatalf("unexpected API %s", path)
		}
		if method == http.MethodGet {
			return []byte(gatewayChart), nil
		}
		var patch map[string]any
		if err := json.Unmarshal(body, &patch); err != nil {
			t.Fatal(err)
		}
		if method != http.MethodPatch || patch["metadata"].(map[string]any)["resourceVersion"] != "8" || len(patch["spec"].(map[string]any)) != 1 {
			t.Fatal("unfenced/broad chart update")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedGatewayAndSafeCaddyRetries(t *testing.T) {
	r := resources(t, services())
	g := r["Gateway/"+gatewayName]
	if g == nil || r["GatewayClass/"+gatewayClassName] == nil {
		t.Fatal("missing Gateway API resources")
	}
	spec := g["spec"].(map[string]any)
	l := spec["listeners"].([]any)[0].(map[string]any)
	if l["port"] != float64(8000) || l["protocol"] != "HTTP" {
		t.Fatal("wrong Traefik entrypoint")
	}
	ns := l["allowedRoutes"].(map[string]any)["namespaces"].(map[string]any)
	if ns["from"] != "Selector" || ns["selector"].(map[string]any)["matchLabels"].(map[string]any)[publicationLabel] != "true" {
		t.Fatal("unrestricted namespace attachment")
	}
	caddy := r["ConfigMap/connect-gateway"]["data"].(map[string]any)["Caddyfile"].(string)
	if strings.Count(caddy, "lb_try_duration 5s") != 1 || !strings.Contains(caddy, "lb_try_interval 100ms") || strings.Contains(caddy, "lb_retry_match") || strings.Contains(caddy, "trusted_proxies") {
		t.Fatal("missing bounded app retries or broadened retry/proxy trust policy")
	}
}

func TestRouteReadinessRequiresCurrentGenerationAndExactParent(t *testing.T) {
	var r routeStatus
	_ = json.Unmarshal([]byte(`{"metadata":{"generation":2},"status":{"parents":[{"controllerName":"traefik.io/gateway-controller","parentRef":{"name":"connect-public","namespace":"deepai-system","sectionName":"http"},"conditions":[{"type":"Accepted","status":"True","observedGeneration":2},{"type":"ResolvedRefs","status":"True","observedGeneration":2}]}]}}`), &r)
	if !publicationReady(r) {
		t.Fatal("ready route rejected")
	}
	r.Status.Parents[0].Conditions[1].ObservedGeneration = 1
	if publicationReady(r) {
		t.Fatal("stale backend resolution accepted")
	}
	r.Status.Parents[0].Conditions[1].ObservedGeneration = 2
	r.Status.Parents[0].ParentRef.SectionName = "other"
	if publicationReady(r) {
		t.Fatal("wrong listener accepted")
	}
}
