package cluster

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func services() ServiceConfig {
	return ServiceConfig{Image: "registry.example.com/connect:v1.0.0", PublicURL: "https://mesh.example.com", Hubs: []HubEndpoint{{Name: "hub-1", Hostname: "relay.example.com"}}, Apps: []string{"app.example.com"}}
}
func resources(t *testing.T, c ServiceConfig) map[string]map[string]any {
	t.Helper()
	b, err := GenerateServices(c)
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Items []map[string]any }
	if err = json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	m := map[string]map[string]any{}
	for _, item := range list.Items {
		meta := item["metadata"].(map[string]any)
		m[item["kind"].(string)+"/"+meta["name"].(string)] = item
	}
	return m
}
func TestServicesSupervisedAndCredentialsSeparated(t *testing.T) {
	c := services()
	c.BootstrapSecret = map[string]string{"server-token": "sensitive"}
	res := resources(t, c)
	for _, name := range []string{"CustomResourceDefinition/networkstates.connect.deepai.cloud", "Deployment/connect-coordinator", "DaemonSet/connect-relay", "DaemonSet/connect-gateway", "Role/connect-coordinator", "Service/connect-coordinator"} {
		if res[name] == nil {
			t.Fatalf("missing %s", name)
		}
	}
	bytes, _ := GenerateServices(c)
	if strings.Contains(string(bytes), "sensitive") {
		t.Fatal("credential exposed in reusable manifest / last-applied annotation")
	}
	d := res["Deployment/connect-coordinator"]
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), `"/readyz"`) || !strings.Contains(string(b), `"/health"`) {
		t.Fatal("coordinator health checks missing")
	}
	relay, _ := json.Marshal(res["DaemonSet/connect-relay"])
	if !strings.Contains(string(relay), "--key-file") || !strings.Contains(string(relay), "derp-key") {
		t.Fatal("relay does not load durable identity from Secret")
	}
	caddy := res["ConfigMap/connect-gateway"]["data"].(map[string]any)["Caddyfile"].(string)
	for _, want := range []string{"connect-coordinator.deepai-system.svc.cluster.local:8080", "127.0.0.1:3340", "traefik.kube-system.svc.cluster.local:80", "@derp path /derp /derp/*"} {
		if !strings.Contains(caddy, want) {
			t.Fatalf("gateway missing %q", want)
		}
	}
}
func TestGatewayUpdatesRollDeployment(t *testing.T) {
	first := resources(t, services())["DaemonSet/connect-gateway"]
	c := services()
	c.Apps = append(c.Apps, "second.example.com")
	second := resources(t, c)["DaemonSet/connect-gateway"]
	annotation := func(m map[string]any) string {
		return m["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["annotations"].(map[string]any)["connect.deepai.cloud/config-hash"].(string)
	}
	if annotation(first) == annotation(second) {
		t.Fatal("gateway will retain stale publication configuration")
	}
}

func TestCredentialBearingWorkloadsRequireProtectedHubLabel(t *testing.T) {
	res := resources(t, services())
	for _, workload := range []string{"Deployment/connect-coordinator", "DaemonSet/connect-relay", "DaemonSet/connect-gateway"} {
		spec := res[workload]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		selector := spec["nodeSelector"].(map[string]any)
		if selector[ProtectedRoleLabel] != "hub" {
			t.Fatalf("%s can expose credentials to a worker that changes its ordinary role label", workload)
		}
		if _, unprotected := selector["connect.deepai.cloud/role"]; unprotected {
			t.Fatalf("%s still relies on a kubelet-controlled role label", workload)
		}
	}
}
func TestServiceValidationRejectsInjectionAndUnpinnedImages(t *testing.T) {
	for _, change := range []func(*ServiceConfig){func(c *ServiceConfig) { c.Image = "connect:latest" }, func(c *ServiceConfig) { c.PublicURL = "http://mesh.example.com" }, func(c *ServiceConfig) { c.Hubs[0].Hostname = "bad\n{thing}" }, func(c *ServiceConfig) {
		c.PublicURL = "https://127.0.0.1"
	}, func(c *ServiceConfig) { c.Apps = []string{"mesh.example.com"} }, func(c *ServiceConfig) { c.TLSCertificate = []byte("not a cert") }} {
		c := services()
		change(&c)
		if _, err := GenerateServices(c); err == nil {
			t.Fatal("unsafe service config accepted")
		}
	}
}
func TestExistingSecretNeverOverwritten(t *testing.T) {
	f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
		return []byte("secret/connect-enrollment"), nil
	}}
	m := newManager(t, config(t), f)
	if err := m.ensureSecret(context.Background(), Namespace, "connect-enrollment", map[string]string{"server-token": "new"}, "Opaque"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || strings.Contains(strings.Join(f.calls[0].args, " "), "create") {
		t.Fatal("resume rotated established credentials")
	}
}
func TestPublishVerifiesServicePort(t *testing.T) {
	f := &fakeRunner{run: func(_ []byte, _ string, args []string) ([]byte, error) {
		return []byte(`{"spec":{"ports":[{"port":8080,"protocol":"TCP"}]}}`), nil
	}}
	m := newManager(t, config(t), f)
	if err := m.Publish(context.Background(), "app.example.com", "default", "app", 8081); err == nil {
		t.Fatal("published nonexistent port")
	}
	if len(f.calls) != 1 {
		t.Fatal("mutated cluster after invalid service")
	}
}

func TestTLSSecretReferenceSurvivesCredentialRedaction(t *testing.T) {
	c := services()
	c.TLSSecretName = "connect-gateway-tls"
	res := resources(t, c)
	gateway, _ := json.Marshal(res["DaemonSet/connect-gateway"])
	if !strings.Contains(string(gateway), `"secretName":"connect-gateway-tls"`) {
		t.Fatal("reconciliation dropped TLS Secret after local credentials were redacted")
	}
	caddy := res["ConfigMap/connect-gateway"]["data"].(map[string]any)["Caddyfile"].(string)
	if !strings.Contains(caddy, "tls /run/connect-tls/tls.crt /run/connect-tls/tls.key") {
		t.Fatal("reconciliation switched existing gateway identity to ACME")
	}
}
