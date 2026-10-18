package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const gatewayName = "connect-public"
const gatewayClassName = "deepai-connect"
const gatewayController = "traefik.io/gateway-controller"
const publicationLabel = "connect.deepai.cloud/publish"
const traefikConfigPath = "/apis/helm.cattle.io/v1/namespaces/kube-system/helmchartconfigs/traefik"

var hubNodesPath = "/api/v1/nodes?labelSelector=" + url.QueryEscape(ProtectedRoleLabel+"=hub")

func gatewayResources(namespace string) []resource {
	class := obj("gateway.networking.k8s.io/v1", "GatewayClass", gatewayClassName, "")
	class["spec"] = resource{"controllerName": gatewayController}
	gateway := obj("gateway.networking.k8s.io/v1", "Gateway", gatewayName, namespace)
	// Caddy terminates public TLS. This listener uses Traefik's container
	// entrypoint (8000), reached through its internal Service on port 80.
	gateway["spec"] = resource{"gatewayClassName": gatewayClassName, "listeners": []any{resource{
		"name": "http", "protocol": "HTTP", "port": 8000,
		"allowedRoutes": resource{"kinds": []any{resource{"kind": "HTTPRoute", "group": "gateway.networking.k8s.io"}}, "namespaces": resource{"from": "Selector", "selector": resource{"matchLabels": resource{publicationLabel: "true"}}}},
	}}}
	return []resource{class, gateway}
}

func trustedHubProxies(data []byte) ([]string, error) {
	var nodes struct {
		Items []struct {
			Metadata struct{ Labels map[string]string }
			Spec     struct {
				PodCIDR  string
				PodCIDRs []string
			}
			Status struct {
				Addresses []struct{ Type, Address string }
			}
		}
	}
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, err
	}
	addresses := []string{}
	for _, n := range nodes.Items {
		if n.Metadata.Labels[ProtectedRoleLabel] != "hub" {
			continue
		}
		// K3s hostNetwork -> local ClusterIP traffic is SNATed to the hub's
		// CNI bridge; cross-hub traffic can use the hub's internal node IP.
		cidrs := append(slices.Clone(n.Spec.PodCIDRs), n.Spec.PodCIDR)
		for _, raw := range cidrs {
			if raw == "" {
				continue
			}
			p, err := netip.ParsePrefix(raw)
			if err != nil || p != p.Masked() || !p.Contains(p.Addr().Next()) {
				return nil, fmt.Errorf("invalid hub pod CIDR %q", raw)
			}
			ip := p.Addr().Next()
			addresses = append(addresses, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
		for _, a := range n.Status.Addresses {
			if a.Type != "InternalIP" {
				continue
			}
			ip, err := netip.ParseAddr(a.Address)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
				return nil, fmt.Errorf("invalid hub internal address %q", a.Address)
			}
			addresses = append(addresses, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
	}
	if nodes.Items == nil {
		return nil, errors.New("Kubernetes node list is missing items")
	}
	slices.Sort(addresses)
	return slices.Compact(addresses), nil
}

// traefikValues owns only Gateway API, proxy trust and the minimum hub placement
// policy. Preserve administrator/chart values, including YAML-formatted input.
func traefikValues(current string, nodes []byte) (string, bool, error) {
	ips, err := trustedHubProxies(nodes)
	if err != nil {
		return "", false, err
	}
	values := map[string]any{}
	if err = yaml.Unmarshal([]byte(current), &values); err != nil {
		return "", false, err
	}
	if values == nil {
		values = map[string]any{}
	}
	before, err := json.Marshal(values)
	if err != nil {
		return "", false, err
	}
	set := func(value any, path ...string) error {
		m := values
		for _, key := range path[:len(path)-1] {
			if m[key] == nil {
				m[key] = map[string]any{}
			}
			next, ok := m[key].(map[string]any)
			if !ok {
				return fmt.Errorf("Traefik value %s must be a mapping", strings.Join(path, "."))
			}
			m = next
		}
		m[path[len(path)-1]] = value
		return nil
	}
	for _, entry := range []struct {
		value any
		path  []string
	}{
		{true, []string{"providers", "kubernetesGateway", "enabled"}},
		{false, []string{"gateway", "enabled"}},
		{false, []string{"gatewayClass", "enabled"}},
		{8000, []string{"ports", "web", "port"}},
		{80, []string{"ports", "web", "exposedPort"}},
		{true, []string{"ports", "web", "expose", "default"}},
		{"ClusterIP", []string{"service", "spec", "type"}},
		{false, []string{"ports", "web", "forwardedHeaders", "insecure"}},
		{ips, []string{"ports", "web", "forwardedHeaders", "trustedIPs"}},
		{"hub", []string{"nodeSelector", ProtectedRoleLabel}},
	} {
		if err = set(entry.value, entry.path...); err != nil {
			return "", false, err
		}
	}
	// The pinned chart v40 moved Service fields under service.spec.
	delete(values["service"].(map[string]any), "type")
	if d, ok := values["deployment"].(map[string]any); ok {
		if n, ok := d["replicas"].(int); ok && n >= 2 {
			// Retain a larger operator-selected replica count.
		} else if err = set(2, "deployment", "replicas"); err != nil {
			return "", false, err
		}
	} else if err = set(2, "deployment", "replicas"); err != nil {
		return "", false, err
	}
	after, err := json.Marshal(values) // JSON is also valid Helm values YAML.
	return string(after), !reflect.DeepEqual(before, after), err
}

func reconcileGatewayChart(ctx context.Context, api InfrastructureAPI) error {
	nodes, err := api(ctx, http.MethodGet, hubNodesPath, nil)
	if err != nil {
		return err
	}
	data, err := api(ctx, http.MethodGet, traefikConfigPath, nil)
	if err != nil {
		return err
	}
	var config struct {
		Metadata struct{ ResourceVersion string }
		Spec     struct{ ValuesContent string }
	}
	if err = json.Unmarshal(data, &config); err != nil {
		return err
	}
	if config.Metadata.ResourceVersion == "" {
		return errors.New("Traefik HelmChartConfig lacks resourceVersion")
	}
	values, changed, err := traefikValues(config.Spec.ValuesContent, nodes)
	if err != nil || !changed {
		return err
	}
	patch, _ := json.Marshal(resource{"metadata": resource{"resourceVersion": config.Metadata.ResourceVersion}, "spec": resource{"valuesContent": values}})
	_, err = api(ctx, http.MethodPatch, traefikConfigPath, patch)
	return err
}

func (m *Manager) ensureGatewayChart(ctx context.Context) error {
	data, err := m.Kubectl(ctx, nil, "-n", "kube-system", "get", "helmchartconfig", "traefik", "--ignore-not-found", "-o", "json")
	if err != nil {
		return fmt.Errorf("K3s Traefik HelmChartConfig: %w", err)
	}
	if len(strings.TrimSpace(string(data))) != 0 {
		return nil
	}
	nodes, err := m.Kubectl(ctx, nil, "get", "--raw", hubNodesPath)
	if err != nil {
		return err
	}
	values, _, err := traefikValues("", nodes)
	if err != nil {
		return err
	}
	config := obj("helm.cattle.io/v1", "HelmChartConfig", "traefik", "kube-system")
	config["spec"] = resource{"valuesContent": values}
	body, _ := json.Marshal(config)
	_, err = m.Kubectl(ctx, body, "create", "-f", "-")
	return err
}
