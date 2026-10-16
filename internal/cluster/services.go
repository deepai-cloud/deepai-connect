package cluster

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const Namespace = "deepai-system"
const CaddyImage = "caddy:2.11.6-alpine"

// HubEndpoint gives each relay its own directly reachable public DNS name. All
// hubs may additionally serve the shared PublicURL through DNS failover.
type HubEndpoint struct{ Name, Hostname, PublicIP string }
type ServiceConfig struct {
	Namespace              string
	Image                  string
	PublicURL              string
	Hubs                   []HubEndpoint
	Replicas               int
	TLSCertificate, TLSKey []byte
	TLSSecretName          string
	// BootstrapSecret is installed once; subsequent reconciliations preserve it.
	BootstrapSecret map[string]string
	Apps            []string
}

type resource map[string]any

func obj(api, kind, name, namespace string) resource {
	meta := resource{"name": name, "labels": resource{"app.kubernetes.io/part-of": "deepai-connect"}}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	return resource{"apiVersion": api, "kind": kind, "metadata": meta}
}

var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$`)

// ValidDomain accepts lowercase, fully qualified ASCII DNS names used by the
// public coordinator, relays and applications. IP literals are not hostnames.
func ValidDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func pinnedImage(image string) bool {
	if !imagePattern.MatchString(image) {
		return false
	}
	if strings.Contains(image, "@sha256:") {
		parts := strings.Split(image, "@sha256:")
		return len(parts) == 2 && len(parts[1]) == 64 && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(parts[1])
	}
	last := image[strings.LastIndex(image, "/")+1:]
	i := strings.LastIndex(last, ":")
	return i > 0 && i < len(last)-1 && last[i+1:] != "latest" && last[i+1:] != "main" && last[i+1:] != "dev"
}
func (c *ServiceConfig) defaultsAndValidate() error {
	if c.Namespace == "" {
		c.Namespace = Namespace
	}
	if !dnsLabel.MatchString(c.Namespace) {
		return errors.New("invalid services namespace")
	}
	if !pinnedImage(c.Image) {
		return errors.New("Connect service image must have an explicit release tag or sha256 digest")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || !ValidDomain(u.Hostname()) || u.Port() != "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("public URL must be an HTTPS DNS origin on port 443")
	}
	if c.Replicas == 0 {
		c.Replicas = 2
	}
	if c.Replicas < 1 || c.Replicas > 5 {
		return errors.New("coordinator replicas must be between one and five")
	}
	seen := map[string]bool{u.Hostname(): true}
	for _, hub := range c.Hubs {
		if !dnsLabel.MatchString(hub.Name) || !ValidDomain(hub.Hostname) {
			return errors.New("each hub needs a valid node name and relay DNS name")
		}
		if hub.PublicIP != "" && net.ParseIP(hub.PublicIP) == nil {
			return errors.New("invalid public hub address")
		}
		seen[hub.Hostname] = true
	}
	for _, host := range c.Apps {
		if !ValidDomain(host) || seen[host] {
			return errors.New("application hostnames must be unique DNS names")
		}
		seen[host] = true
	}
	if c.TLSSecretName != "" && !dnsLabel.MatchString(c.TLSSecretName) {
		return errors.New("invalid gateway TLS Secret name")
	}
	if len(c.TLSCertificate) > 0 || len(c.TLSKey) > 0 {
		if c.TLSSecretName == "" {
			c.TLSSecretName = "connect-gateway-tls"
		}
		if _, err := tls.X509KeyPair(c.TLSCertificate, c.TLSKey); err != nil {
			return fmt.Errorf("invalid gateway TLS identity: %w", err)
		}
	}
	return nil
}

func gatewayConfig(c ServiceConfig) string {
	u, _ := url.Parse(c.PublicURL)
	var b strings.Builder
	b.WriteString("{\n  admin off\n}\n")
	tlsDirective := ""
	if c.TLSSecretName != "" {
		tlsDirective = "  tls /run/connect-tls/tls.crt /run/connect-tls/tls.key\n"
	}
	fmt.Fprintf(&b, "%s {\n%s  @derp path /derp /derp/* /generate_204\n  handle @derp {\n    reverse_proxy 127.0.0.1:3340\n  }\n  handle {\n    reverse_proxy connect-coordinator.%s.svc.cluster.local:8080\n  }\n}\n", u.Hostname(), tlsDirective, c.Namespace)
	relays := make([]string, 0, len(c.Hubs))
	seen := map[string]bool{u.Hostname(): true}
	for _, hub := range c.Hubs {
		if !seen[hub.Hostname] {
			seen[hub.Hostname] = true
			relays = append(relays, hub.Hostname)
		}
	}
	sort.Strings(relays)
	for _, host := range relays {
		fmt.Fprintf(&b, "%s {\n%s  reverse_proxy 127.0.0.1:3340\n}\n", host, tlsDirective)
	}
	for _, host := range c.Apps {
		fmt.Fprintf(&b, "%s {\n%s  reverse_proxy traefik.kube-system.svc.cluster.local:80\n}\n", host, tlsDirective)
	}
	b.WriteString("http://127.0.0.1:3341 {\n  respond /health 200\n}\n")
	return b.String()
}

// GenerateServices builds the declarative control plane, relays and public
// ingress. Credential creation is intentionally separate from reconciliation:
// applying this manifest never rotates a durable coordinator identity.
func GenerateServices(c ServiceConfig) ([]byte, error) {
	if err := c.defaultsAndValidate(); err != nil {
		return nil, err
	}
	var items []resource
	items = append(items, obj("v1", "Namespace", c.Namespace, ""))
	crd := obj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "networkstates.connect.deepai.cloud", "")
	crd["spec"] = resource{"group": "connect.deepai.cloud", "scope": "Namespaced", "names": resource{"plural": "networkstates", "singular": "networkstate", "kind": "NetworkState"}, "versions": []any{resource{"name": "v1alpha1", "served": true, "storage": true, "schema": resource{"openAPIV3Schema": resource{"type": "object", "properties": resource{"spec": resource{"type": "object", "x-kubernetes-preserve-unknown-fields": true}}}}}}}
	items = append(items, crd, obj("v1", "ServiceAccount", "connect-coordinator", c.Namespace))
	role := obj("rbac.authorization.k8s.io/v1", "Role", "connect-coordinator", c.Namespace)
	role["rules"] = []any{
		resource{"apiGroups": []string{"connect.deepai.cloud"}, "resources": []string{"networkstates"}, "verbs": []string{"get", "create", "update"}},
		resource{"apiGroups": []string{""}, "resources": []string{"secrets"}, "verbs": []string{"create"}},
		resource{"apiGroups": []string{""}, "resources": []string{"secrets"}, "resourceNames": []string{"connect-coordinator-keys", "connect-enrollment"}, "verbs": []string{"get"}},
		resource{"apiGroups": []string{"coordination.k8s.io"}, "resources": []string{"leases"}, "verbs": []string{"get", "create", "update"}},
	}
	binding := obj("rbac.authorization.k8s.io/v1", "RoleBinding", "connect-coordinator", c.Namespace)
	binding["roleRef"] = resource{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "connect-coordinator"}
	binding["subjects"] = []any{resource{"kind": "ServiceAccount", "name": "connect-coordinator", "namespace": c.Namespace}}
	items = append(items, role, binding)
	nodeRole := obj("rbac.authorization.k8s.io/v1", "ClusterRole", "connect-coordinator-node-reader", "")
	nodeRole["rules"] = []any{resource{"apiGroups": []string{""}, "resources": []string{"nodes"}, "verbs": []string{"get", "list"}}, resource{"nonResourceURLs": []string{"/readyz"}, "verbs": []string{"get"}}}
	nodeBinding := obj("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "connect-coordinator-node-reader", "")
	nodeBinding["roleRef"] = resource{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "connect-coordinator-node-reader"}
	nodeBinding["subjects"] = binding["subjects"]
	items = append(items, nodeRole, nodeBinding)
	bootstrapRole := obj("rbac.authorization.k8s.io/v1", "Role", "connect-bootstrap-tokens", "kube-system")
	bootstrapRole["rules"] = []any{resource{"apiGroups": []string{""}, "resources": []string{"secrets"}, "verbs": []string{"create", "get"}}}
	bootstrapBinding := obj("rbac.authorization.k8s.io/v1", "RoleBinding", "connect-bootstrap-tokens", "kube-system")
	bootstrapBinding["roleRef"] = resource{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "connect-bootstrap-tokens"}
	bootstrapBinding["subjects"] = binding["subjects"]
	items = append(items, bootstrapRole, bootstrapBinding)
	infrastructureRole := obj("rbac.authorization.k8s.io/v1", "Role", "connect-infrastructure-availability", "kube-system")
	infrastructureRole["rules"] = []any{resource{"apiGroups": []string{"apps"}, "resources": []string{"deployments"}, "resourceNames": []string{"coredns", "traefik"}, "verbs": []string{"get", "patch"}}}
	infrastructureBinding := obj("rbac.authorization.k8s.io/v1", "RoleBinding", "connect-infrastructure-availability", "kube-system")
	infrastructureBinding["roleRef"] = resource{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "connect-infrastructure-availability"}
	infrastructureBinding["subjects"] = binding["subjects"]
	items = append(items, infrastructureRole, infrastructureBinding)
	hubMembership, _ := json.Marshal(c.Hubs)
	labels := resource{"app": "connect-coordinator"}
	deploy := obj("apps/v1", "Deployment", "connect-coordinator", c.Namespace)
	deploy["spec"] = resource{"replicas": c.Replicas, "selector": resource{"matchLabels": labels}, "strategy": resource{"rollingUpdate": resource{"maxUnavailable": 0, "maxSurge": 1}}, "template": resource{"metadata": resource{"labels": labels, "annotations": resource{"connect.deepai.cloud/hubs-hash": fmt.Sprintf("%x", sha256.Sum256(hubMembership))}}, "spec": resource{
		"serviceAccountName": "connect-coordinator", "volumes": []any{resource{"name": "bootstrap", "secret": resource{"secretName": "connect-enrollment", "optional": true}}}, "nodeSelector": resource{ProtectedRoleLabel: "hub"},
		"affinity":   resource{"podAntiAffinity": resource{"preferredDuringSchedulingIgnoredDuringExecution": []any{resource{"weight": 100, "podAffinityTerm": resource{"labelSelector": resource{"matchLabels": labels}, "topologyKey": "kubernetes.io/hostname"}}}}},
		"containers": []any{resource{"name": "coordinator", "image": c.Image, "volumeMounts": []any{resource{"name": "bootstrap", "mountPath": "/etc/deepai/credentials", "readOnly": true}}, "imagePullPolicy": "IfNotPresent", "args": []string{"coordinator", "--listen", ":8080", "--namespace", c.Namespace, "--bootstrap-secret-dir", "/etc/deepai/credentials"}, "ports": []any{resource{"name": "http", "containerPort": 8080}}, "readinessProbe": httpProbe("/readyz", 8080, ""), "livenessProbe": httpProbe("/health", 8080, ""), "resources": resource{"requests": resource{"cpu": "100m", "memory": "128Mi"}, "limits": resource{"memory": "512Mi"}}, "securityContext": resource{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "runAsUser": 65532, "capabilities": resource{"drop": []string{"ALL"}}}}},
	}}}
	svc := obj("v1", "Service", "connect-coordinator", c.Namespace)
	svc["spec"] = resource{"selector": labels, "ports": []any{resource{"name": "http", "port": 8080, "targetPort": "http"}}}
	pdb := obj("policy/v1", "PodDisruptionBudget", "connect-coordinator", c.Namespace)
	pdb["spec"] = resource{"maxUnavailable": 1, "selector": resource{"matchLabels": labels}}
	items = append(items, deploy, svc, pdb)
	// The relay is one instance per physical hub. Its identity comes from the
	// durable Kubernetes Secret shared by the cluster-managed relay instances.
	relayLabels := resource{"app": "connect-relay"}
	relay := obj("apps/v1", "DaemonSet", "connect-relay", c.Namespace)
	relay["spec"] = resource{"selector": resource{"matchLabels": relayLabels}, "updateStrategy": resource{"type": "RollingUpdate", "rollingUpdate": resource{"maxUnavailable": 1}}, "template": resource{"metadata": resource{"labels": relayLabels}, "spec": resource{
		"hostNetwork": true, "dnsPolicy": "ClusterFirstWithHostNet", "automountServiceAccountToken": false, "nodeSelector": resource{ProtectedRoleLabel: "hub"},
		"containers": []any{resource{"name": "relay", "image": c.Image, "args": []string{"relay", "--listen", "127.0.0.1:3340", "--stun-listen", ":3478", "--verify-url", c.PublicURL + "/verify", "--state-dir", "/var/lib/connect-relay", "--key-file", "/etc/deepai/credentials/derp-key"}, "readinessProbe": httpProbe("/health", 3340, "127.0.0.1"), "livenessProbe": httpProbe("/health", 3340, "127.0.0.1"), "volumeMounts": []any{resource{"name": "state", "mountPath": "/var/lib/connect-relay"}, resource{"name": "identity", "mountPath": "/etc/deepai/credentials", "readOnly": true}}, "resources": resource{"requests": resource{"cpu": "50m", "memory": "64Mi"}, "limits": resource{"memory": "512Mi"}}, "securityContext": resource{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": resource{"drop": []string{"ALL"}}}}},
		"volumes":    []any{resource{"name": "state", "emptyDir": resource{}}, resource{"name": "identity", "secret": resource{"secretName": "connect-enrollment", "items": []any{resource{"key": "derp-key", "path": "derp-key"}}}}},
	}}}
	items = append(items, relay)
	cm := obj("v1", "ConfigMap", "connect-gateway", c.Namespace)
	cm["data"] = resource{"Caddyfile": gatewayConfig(c)}
	items = append(items, cm)
	gatewayLabels := resource{"app": "connect-gateway"}
	volumes := []any{resource{"name": "config", "configMap": resource{"name": "connect-gateway"}}, resource{"name": "data", "hostPath": resource{"path": "/var/lib/deepai-connect/gateway", "type": "DirectoryOrCreate"}}, resource{"name": "cache", "emptyDir": resource{}}}
	mounts := []any{resource{"name": "config", "mountPath": "/etc/caddy", "readOnly": true}, resource{"name": "data", "mountPath": "/data"}, resource{"name": "cache", "mountPath": "/config"}}
	if c.TLSSecretName != "" {
		volumes = append(volumes, resource{"name": "tls", "secret": resource{"secretName": c.TLSSecretName}})
		mounts = append(mounts, resource{"name": "tls", "mountPath": "/run/connect-tls", "readOnly": true})
	}
	gateway := obj("apps/v1", "DaemonSet", "connect-gateway", c.Namespace)
	gateway["spec"] = resource{"selector": resource{"matchLabels": gatewayLabels}, "updateStrategy": resource{"type": "RollingUpdate", "rollingUpdate": resource{"maxUnavailable": 1}}, "template": resource{"metadata": resource{"labels": gatewayLabels, "annotations": resource{"connect.deepai.cloud/config-hash": fmt.Sprintf("%x", sha256.Sum256([]byte(gatewayConfig(c))))}}, "spec": resource{
		"hostNetwork": true, "dnsPolicy": "ClusterFirstWithHostNet", "automountServiceAccountToken": false, "nodeSelector": resource{ProtectedRoleLabel: "hub"}, "volumes": volumes,
		"containers": []any{resource{"name": "gateway", "image": CaddyImage, "args": []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"}, "volumeMounts": mounts, "readinessProbe": httpProbe("/health", 3341, "127.0.0.1"), "livenessProbe": httpProbe("/health", 3341, "127.0.0.1"), "resources": resource{"requests": resource{"cpu": "50m", "memory": "64Mi"}, "limits": resource{"memory": "512Mi"}}, "securityContext": resource{"allowPrivilegeEscalation": false, "capabilities": resource{"drop": []string{"ALL"}, "add": []string{"NET_BIND_SERVICE"}}}}},
	}}}
	items = append(items, gateway)
	return json.MarshalIndent(resource{"apiVersion": "v1", "kind": "List", "items": items}, "", "  ")
}
func httpProbe(path string, port int, host string) resource {
	get := resource{"path": path, "port": port}
	if host != "" {
		get["host"] = host
	}
	return resource{"httpGet": get, "initialDelaySeconds": 2, "periodSeconds": 10, "timeoutSeconds": 3, "failureThreshold": 6}
}

func (m *Manager) ensureSecret(ctx context.Context, namespace, name string, data map[string]string, kind string) error {
	// Do not put Secret bodies in kubectl last-applied annotations or overwrite
	// existing credentials when a hub is resumed or another hub joins.
	out, err := m.kubectl(ctx, nil, "-n", namespace, "get", "secret", name, "--ignore-not-found", "-o", "name")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "" {
		return nil
	}
	secret := obj("v1", "Secret", name, namespace)
	secret["type"] = kind
	secret["stringData"] = data
	body, _ := json.Marshal(secret)
	if _, err = m.kubectl(ctx, body, "create", "-f", "-"); err != nil {
		// A concurrent hub may have won creation. Any other failure stays fatal.
		found, e := m.kubectl(ctx, nil, "-n", namespace, "get", "secret", name, "-o", "name")
		if e == nil && strings.TrimSpace(string(found)) != "" {
			return nil
		}
		return err
	}
	return nil
}
func (m *Manager) ApplyServices(ctx context.Context, c ServiceConfig) error {
	if err := m.ReconcileServices(ctx, c); err != nil {
		return err
	}
	return m.WaitServicesReady(ctx, c)
}

// ReconcileServices creates the API schema, credentials and workloads without
// waiting for coordinator readiness. First-hub bootstrap commits its durable
// network membership after this step and before WaitServicesReady, so readiness
// never has to claim an empty or missing network registry is healthy.
func (m *Manager) ReconcileServices(ctx context.Context, c ServiceConfig) error {
	if m.Config.Role != "hub" {
		return errors.New("only hubs can reconcile cluster services")
	}
	if err := c.defaultsAndValidate(); err != nil {
		return err
	}
	manifest, err := GenerateServices(c)
	if err != nil {
		return err
	}
	// Namespace must exist before credential creation. Apply non-secret resources
	// first; pods remain Pending until their optional TLS secret exists.
	if _, err = m.kubectl(ctx, manifest, "apply", "-f", "-"); err != nil {
		return err
	}
	if _, err = m.kubectl(ctx, nil, "wait", "--for=condition=Established", "--timeout=60s", "crd/networkstates.connect.deepai.cloud"); err != nil {
		return err
	}
	if len(c.BootstrapSecret) > 0 {
		if err = m.ensureSecret(ctx, c.Namespace, "connect-enrollment", c.BootstrapSecret, "Opaque"); err != nil {
			return err
		}
	}
	if len(c.TLSCertificate) > 0 {
		if err = m.ensureSecret(ctx, c.Namespace, c.TLSSecretName, map[string]string{"tls.crt": string(c.TLSCertificate), "tls.key": string(c.TLSKey)}, "kubernetes.io/tls"); err != nil {
			return err
		}
	}
	return m.reconcileInfrastructure(ctx)
}

// WaitServicesReady waits for each Kubernetes-managed service to become ready.
// The caller must have initialized NetworkState before waiting on the first hub.
func (m *Manager) WaitServicesReady(ctx context.Context, c ServiceConfig) error {
	if m.Config.Role != "hub" {
		return errors.New("only hubs can reconcile cluster services")
	}
	if err := c.defaultsAndValidate(); err != nil {
		return err
	}
	for _, name := range infrastructureDeployments {
		if _, err := m.kubectl(ctx, nil, "-n", "kube-system", "rollout", "status", "deployment/"+name, "--timeout=180s"); err != nil {
			return err
		}
	}
	for _, workload := range []string{"deployment/connect-coordinator", "daemonset/connect-relay", "daemonset/connect-gateway"} {
		if _, err := m.kubectl(ctx, nil, "-n", c.Namespace, "rollout", "status", workload, "--timeout=180s"); err != nil {
			return err
		}
	}
	return nil
}

// Kubectl uses this installation's private kubeconfig and overlay API endpoint.
func (m *Manager) Kubectl(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	return m.kubectl(ctx, input, args...)
}

// Publish creates a Traefik Ingress after checking its Service. The caller also
// adds hostname to ServiceConfig.Apps and reconciles gateway configuration.
func (m *Manager) Publish(ctx context.Context, hostname, namespace, service string, port int) error {
	if !ValidDomain(hostname) || !dnsLabel.MatchString(namespace) || !dnsLabel.MatchString(service) || port < 1 || port > 65535 {
		return errors.New("publish requires a DNS hostname, namespace/service and valid TCP port")
	}
	data, err := m.kubectl(ctx, nil, "-n", namespace, "get", "service", service, "-o", "json")
	if err != nil {
		return err
	}
	var existing struct {
		Spec struct {
			Ports []struct {
				Port     int
				Protocol string
			}
		}
	}
	if err = json.Unmarshal(data, &existing); err != nil {
		return err
	}
	found := false
	for _, p := range existing.Spec.Ports {
		if p.Port == port && (p.Protocol == "TCP" || p.Protocol == "") {
			found = true
		}
	}
	if !found {
		return errors.New("requested TCP port is not exposed by the Kubernetes Service")
	}
	sum := sha256.Sum256([]byte(hostname))
	name := fmt.Sprintf("connect-%x", sum[:10])
	ingress := obj("networking.k8s.io/v1", "Ingress", name, namespace)
	ingress["spec"] = resource{"ingressClassName": "traefik", "rules": []any{resource{"host": hostname, "http": resource{"paths": []any{resource{"path": "/", "pathType": "Prefix", "backend": resource{"service": resource{"name": service, "port": resource{"number": port}}}}}}}}}
	body, _ := json.Marshal(ingress)
	// The hostname is global even though Ingress objects are namespaced. Use
	// the existing cluster lease so simultaneous publishers cannot both pass
	// the collision check and create competing Traefik routes.
	return m.withServicesLease(ctx, func(held context.Context) error {
		data, err := m.kubectl(held, nil, "get", "ingress", "--all-namespaces", "-o", "json")
		if err != nil {
			return err
		}
		var existing struct {
			Items []struct {
				Metadata struct {
					Name, Namespace string
					Labels          map[string]string
				}
				Spec struct{ Rules []struct{ Host string } }
			}
		}
		if err := json.Unmarshal(data, &existing); err != nil {
			return err
		}
		for _, prior := range existing.Items {
			ours := prior.Metadata.Namespace == namespace && prior.Metadata.Name == name
			if ours && prior.Metadata.Labels["app.kubernetes.io/part-of"] != "deepai-connect" {
				return errors.New("publication Ingress name is owned by another application")
			}
			for _, rule := range prior.Spec.Rules {
				if rule.Host == hostname && !ours {
					return fmt.Errorf("hostname %s is already published by Ingress %s/%s; remove that route explicitly before moving it", hostname, prior.Metadata.Namespace, prior.Metadata.Name)
				}
			}
		}
		_, err = m.kubectl(held, body, "apply", "-f", "-")
		return err
	})
}
