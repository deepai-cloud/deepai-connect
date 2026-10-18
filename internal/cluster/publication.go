package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type routeCondition struct {
	Type, Status, Reason, Message string
	ObservedGeneration            int64
}

type routeStatus struct {
	Metadata struct {
		Name, Namespace, UID, ResourceVersion string
		Generation                            int64
		Labels                                map[string]string
		Annotations                           map[string]string
	}
	Spec struct {
		Hostnames        []string
		IngressClassName string
		TLS              []json.RawMessage
		DefaultBackend   json.RawMessage
		Rules            []struct {
			Host string
			HTTP struct {
				Paths []struct {
					Path, PathType string
					Backend        struct {
						Service struct {
							Name string
							Port struct {
								Number int
								Name   string
							}
						}
					}
				}
			}
		}
	}
	Status struct {
		Conditions []routeCondition
		Parents    []struct {
			ControllerName string
			ParentRef      struct{ Group, Kind, Name, Namespace, SectionName string }
			Conditions     []routeCondition
		}
	}
}

func publicationName(host string) string {
	sum := sha256.Sum256([]byte(host))
	return fmt.Sprintf("connect-%x", sum[:10])
}

func hostsOverlap(a, b string) bool {
	return a == b || a == "" || b == "" ||
		(strings.HasPrefix(a, "*.") && strings.HasSuffix(b, a[1:])) ||
		(strings.HasPrefix(b, "*.") && strings.HasSuffix(a, b[1:]))
}

func conditionsReady(conditions []routeCondition, generation int64, types ...string) bool {
	if generation < 1 {
		return false
	}
	for _, typ := range types {
		found := false
		for _, c := range conditions {
			if c.Type == typ && c.Status == "True" && c.ObservedGeneration == generation {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (m *Manager) waitGatewayResource(ctx context.Context, kind, namespace, name string, ready func(routeStatus) bool) error {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	for {
		data, err := m.Kubectl(ctx, nil, "-n", namespace, "get", kind, name, "-o", "json")
		if err != nil {
			return err
		}
		var status routeStatus
		if err = json.Unmarshal(data, &status); err != nil {
			return err
		}
		if ready(status) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s %s/%s to accept the current generation: %w", kind, namespace, name, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func (m *Manager) waitGatewayReady(ctx context.Context, namespace string) error {
	return m.waitGatewayResource(ctx, "gateway", namespace, gatewayName, func(r routeStatus) bool {
		return conditionsReady(r.Status.Conditions, r.Metadata.Generation, "Accepted", "Programmed")
	})
}

func publicationReady(r routeStatus) bool {
	for _, p := range r.Status.Parents {
		if p.ControllerName == gatewayController && p.ParentRef.Name == gatewayName && p.ParentRef.Namespace == Namespace && p.ParentRef.SectionName == "http" &&
			(p.ParentRef.Group == "" || p.ParentRef.Group == "gateway.networking.k8s.io") && (p.ParentRef.Kind == "" || p.ParentRef.Kind == "Gateway") &&
			conditionsReady(p.Conditions, r.Metadata.Generation, "Accepted", "ResolvedRefs") {
			return true
		}
	}
	return false
}

func legacyPublication(r routeStatus, hostname string) bool {
	if len(r.Spec.TLS) != 0 || len(r.Spec.DefaultBackend) != 0 || r.Spec.IngressClassName != "traefik" || len(r.Spec.Rules) != 1 || r.Spec.Rules[0].Host != hostname || len(r.Spec.Rules[0].HTTP.Paths) != 1 {
		return false
	}
	p := r.Spec.Rules[0].HTTP.Paths[0]
	if p.Path != "/" || p.PathType != "Prefix" || p.Backend.Service.Name == "" || p.Backend.Service.Port.Number < 1 {
		return false
	}
	// Administrator-added middleware/redirect annotations may have behavior
	// that cannot be represented by publish's simple HTTPRoute. Never delete it.
	for key := range r.Metadata.Annotations {
		if key != "kubectl.kubernetes.io/last-applied-configuration" {
			return false
		}
	}
	return r.Metadata.UID != "" && r.Metadata.ResourceVersion != ""
}

// Publish creates an HTTPRoute after validating the Service and the global
// hostname claim. Existing generated Ingresses are removed only after the new
// route is accepted and all its references resolve at the current generation.
// The caller persists hostname in ServiceConfig.Apps and reconciles Caddy.
func (m *Manager) Publish(ctx context.Context, hostname, namespace, service string, port int) error {
	if !ValidDomain(hostname) || !dnsLabel.MatchString(namespace) || !dnsLabel.MatchString(service) || port < 1 || port > 65535 {
		return errors.New("publish requires a DNS hostname, namespace/service and valid TCP port")
	}
	data, err := m.Kubectl(ctx, nil, "-n", namespace, "get", "service", service, "-o", "json")
	if err != nil {
		return err
	}
	var svc struct {
		Spec struct {
			Type  string
			Ports []struct {
				Port     int
				Protocol string
			}
		}
	}
	if err = json.Unmarshal(data, &svc); err != nil {
		return err
	}
	if svc.Spec.Type == "ExternalName" {
		return errors.New("publish requires a cluster Service, not ExternalName")
	}
	found := false
	for _, p := range svc.Spec.Ports {
		if p.Port == port && (p.Protocol == "TCP" || p.Protocol == "") {
			found = true
		}
	}
	if !found {
		return errors.New("requested TCP port is not exposed by the Kubernetes Service")
	}
	name := publicationName(hostname)
	return m.withServicesLease(ctx, func(held context.Context) error {
		var legacy *routeStatus
		var version string
		for _, kind := range []string{"ingress", "httproute"} {
			data, err := m.Kubectl(held, nil, "get", kind, "--all-namespaces", "-o", "json")
			if err != nil {
				return err
			}
			var list struct{ Items []routeStatus }
			if err = json.Unmarshal(data, &list); err != nil {
				return err
			}
			for _, prior := range list.Items {
				ours := prior.Metadata.Namespace == namespace && prior.Metadata.Name == name
				if ours && prior.Metadata.Labels["app.kubernetes.io/part-of"] != "deepai-connect" {
					return fmt.Errorf("publication %s name is owned by another application", kind)
				}
				hosts := prior.Spec.Hostnames
				if kind == "ingress" {
					hosts = nil
					for _, rule := range prior.Spec.Rules {
						hosts = append(hosts, rule.Host)
					}
				}
				if len(hosts) == 0 {
					hosts = []string{""}
				}
				for _, host := range hosts {
					if hostsOverlap(host, hostname) && !ours {
						return fmt.Errorf("hostname %s is already claimed by %s %s/%s; remove or migrate that route explicitly", hostname, kind, prior.Metadata.Namespace, prior.Metadata.Name)
					}
				}
				if ours {
					if kind == "ingress" {
						if !legacyPublication(prior, hostname) {
							return errors.New("managed Ingress was customized; migrate it explicitly before publishing")
						}
						legacy = &prior
					} else {
						version = prior.Metadata.ResourceVersion
					}
				}
			}
		}
		if err := m.waitGatewayReady(held, Namespace); err != nil {
			return err
		}
		if _, err := m.Kubectl(held, nil, "label", "namespace", namespace, publicationLabel+"=true", "--overwrite"); err != nil {
			return err
		}
		route := obj("gateway.networking.k8s.io/v1", "HTTPRoute", name, namespace)
		if version != "" {
			route["metadata"].(resource)["resourceVersion"] = version
		}
		route["spec"] = resource{
			"parentRefs": []any{resource{"name": gatewayName, "namespace": Namespace, "sectionName": "http"}},
			"hostnames":  []string{hostname},
			"rules":      []any{resource{"matches": []any{resource{"path": resource{"type": "PathPrefix", "value": "/"}}}, "backendRefs": []any{resource{"name": service, "port": port}}}},
		}
		body, _ := json.Marshal(route)
		verb := "create"
		if version != "" {
			verb = "replace"
		}
		if _, err := m.Kubectl(held, body, verb, "-f", "-"); err != nil {
			return err
		}
		if err := m.waitGatewayResource(held, "httproute", namespace, name, publicationReady); err != nil {
			return err
		}
		if legacy != nil {
			// A user may edit the old route while the controller is reconciling.
			// Delete only the exact object/version validated above.
			options, _ := json.Marshal(resource{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": resource{"uid": legacy.Metadata.UID, "resourceVersion": legacy.Metadata.ResourceVersion}})
			_, err := m.Kubectl(held, options, "delete", "--raw", "/apis/networking.k8s.io/v1/namespaces/"+namespace+"/ingresses/"+name, "-f", "-")
			return err
		}
		return nil
	})
}
