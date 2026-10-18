package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type publicationRunner struct {
	servicesAPIRunner
	publicationMu sync.Mutex
	ingresses     map[string]resource
	routes        map[string]resource
	routeFailure  bool
	deleteFailure bool
}

func (r *publicationRunner) Run(ctx context.Context, body []byte, command string, args ...string) ([]byte, error) {
	if slices.Contains(args, "get") && slices.Contains(args, "service") {
		return []byte(`{"spec":{"ports":[{"port":8080,"protocol":"TCP"}]}}`), nil
	}
	var object resource
	if len(body) > 0 {
		_ = json.Unmarshal(body, &object)
	}
	list := slices.Contains(args, "--all-namespaces")
	routeGet := slices.Contains(args, "get") && slices.Contains(args, "httproute") && !list
	routeWrite := object["kind"] == "HTTPRoute"
	remove := slices.Contains(args, "delete")
	label := slices.Contains(args, "label")
	if !list && !routeGet && !routeWrite && !remove && !label {
		return r.servicesAPIRunner.Run(ctx, body, command, args...)
	}
	r.mu.Lock()
	held := r.lease != nil && r.lease.Spec.HolderIdentity != ""
	r.mu.Unlock()
	if !held {
		return nil, errors.New("publication checked or changed without cluster lease")
	}
	r.publicationMu.Lock()
	defer r.publicationMu.Unlock()
	if label {
		return nil, nil
	}
	if list {
		items := []resource{}
		objects := r.ingresses
		if slices.Contains(args, "httproute") {
			objects = r.routes
		}
		for _, o := range objects {
			items = append(items, o)
		}
		return json.Marshal(resource{"items": items})
	}
	if routeGet {
		if r.routeFailure {
			return nil, errors.New("route never accepted")
		}
		ns := args[slices.Index(args, "-n")+1]
		name := args[slices.Index(args, "httproute")+1]
		return json.Marshal(r.routes[ns+"/"+name])
	}
	if remove {
		if r.deleteFailure {
			return nil, errors.New("resource version conflict")
		}
		p := object["preconditions"].(map[string]any)
		for key, old := range r.ingresses {
			meta := old["metadata"].(map[string]any)
			if p["uid"] == meta["uid"] && p["resourceVersion"] == meta["resourceVersion"] {
				delete(r.ingresses, key)
				return nil, nil
			}
		}
		return nil, errors.New("deletion lacked original UID/version")
	}
	meta := object["metadata"].(map[string]any)
	key := meta["namespace"].(string) + "/" + meta["name"].(string)
	if r.routes == nil {
		r.routes = map[string]resource{}
	}
	if old := r.routes[key]; old != nil {
		if !slices.Contains(args, "replace") || meta["resourceVersion"] != old["metadata"].(map[string]any)["resourceVersion"] {
			return nil, errors.New("unfenced route replacement")
		}
	} else if !slices.Contains(args, "create") {
		return nil, errors.New("unexpected replace")
	}
	meta["generation"] = float64(1)
	meta["resourceVersion"] = "9"
	object["status"] = resource{"parents": []any{resource{"controllerName": gatewayController, "parentRef": resource{"name": gatewayName, "namespace": Namespace, "sectionName": "http"}, "conditions": []any{resource{"type": "Accepted", "status": "True", "observedGeneration": 1}, resource{"type": "ResolvedRefs", "status": "True", "observedGeneration": 1}}}}}
	r.routes[key] = object
	return nil, nil
}

func TestPublicationUpdatesOwnedRouteAndRejectsNamespaceCollision(t *testing.T) {
	r := &publicationRunner{}
	m, err := New(config(t), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"original", "replacement"} {
		if err := m.Publish(context.Background(), "app.example.com", "first", service, 8080); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.routes) != 1 {
		t.Fatal("created another route")
	}
	for _, route := range r.routes {
		spec := route["spec"].(map[string]any)
		backend := spec["rules"].([]any)[0].(map[string]any)["backendRefs"].([]any)[0].(map[string]any)
		if backend["name"] != "replacement" || backend["port"] != float64(8080) {
			t.Fatal("backend update missing")
		}
	}
	before, _ := json.Marshal(r.routes)
	if err := m.Publish(context.Background(), "app.example.com", "second", "different", 8080); err == nil {
		t.Fatal("competing namespace accepted")
	}
	after, _ := json.Marshal(r.routes)
	if string(before) != string(after) {
		t.Fatal("rejected publish mutated routes")
	}
	for _, route := range r.routes {
		route["metadata"].(map[string]any)["labels"] = map[string]any{"app.kubernetes.io/part-of": "other"}
	}
	if err := m.Publish(context.Background(), "app.example.com", "first", "different", 8080); err == nil {
		t.Fatal("overwrote foreign route")
	}
}

func TestConcurrentPublishersCannotClaimHostnameInDifferentNamespaces(t *testing.T) {
	r := &publicationRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start, results := make(chan struct{}), make(chan error, 2)
	for _, ns := range []string{"first", "second"} {
		m, err := New(config(t), r)
		if err != nil {
			t.Fatal(err)
		}
		m.Config.Name = ns
		go func() { <-start; results <- m.Publish(ctx, "app.example.com", ns, "app", 8080) }()
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 || len(r.routes) != 1 {
		t.Fatalf("competing claims: %d, %d", successes, len(r.routes))
	}
}

func legacyFixture(t *testing.T) resource {
	t.Helper()
	var r resource
	raw := fmt.Sprintf(`{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":%q,"namespace":"first","uid":"original","resourceVersion":"7","labels":{"app.kubernetes.io/part-of":"deepai-connect"}},"spec":{"ingressClassName":"traefik","rules":[{"host":"app.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"original","port":{"number":8080}}}}]}}]}}`, publicationName("app.example.com"))
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLegacyIngressMigratesOnlyAfterAcceptedRoute(t *testing.T) {
	for _, mode := range []string{"success", "rejected", "changed"} {
		t.Run(mode, func(t *testing.T) {
			r := &publicationRunner{ingresses: map[string]resource{"first/legacy": legacyFixture(t)}, routeFailure: mode == "rejected", deleteFailure: mode == "changed"}
			m, _ := New(config(t), r)
			err := m.Publish(context.Background(), "app.example.com", "first", "replacement", 8080)
			if mode == "success" {
				if err != nil || len(r.ingresses) != 0 {
					t.Fatalf("migration: %v", err)
				}
			} else if err == nil || len(r.ingresses) != 1 {
				t.Fatal("deleted old route despite failure")
			}
		})
	}
}

func TestPublishRejectsWildcardAndCustomLegacyClaims(t *testing.T) {
	for _, kind := range []string{"ingress", "httproute"} {
		t.Run(kind, func(t *testing.T) {
			foreign := resource{"metadata": resource{"name": "foreign", "namespace": "other"}, "spec": resource{"rules": []any{resource{"host": "*.example.com"}}, "hostnames": []string{"*.example.com"}}}
			raw, _ := json.Marshal(foreign)
			_ = json.Unmarshal(raw, &foreign)
			r := &publicationRunner{}
			if kind == "ingress" {
				r.ingresses = map[string]resource{"foreign": foreign}
			} else {
				r.routes = map[string]resource{"foreign": foreign}
			}
			m, _ := New(config(t), r)
			if err := m.Publish(context.Background(), "app.example.com", "first", "app", 8080); err == nil || !strings.Contains(err.Error(), "already claimed") {
				t.Fatalf("wildcard collision: %v", err)
			}
		})
	}
	r := &publicationRunner{ingresses: map[string]resource{"first/legacy": legacyFixture(t)}}
	r.ingresses["first/legacy"]["metadata"].(map[string]any)["annotations"] = map[string]any{"traefik.ingress.kubernetes.io/router.middlewares": "custom"}
	m, _ := New(config(t), r)
	if err := m.Publish(context.Background(), "app.example.com", "first", "app", 8080); err == nil || len(r.routes) > 0 || len(r.ingresses) != 1 {
		t.Fatal("customized legacy route replaced")
	}
}

func TestLegacyIngressTLSAndDefaultBackendRequireExplicitMigration(t *testing.T) {
	for _, field := range []string{"tls", "defaultBackend"} {
		t.Run(field, func(t *testing.T) {
			old := legacyFixture(t)
			if field == "tls" {
				old["spec"].(map[string]any)[field] = []any{map[string]any{"secretName": "custom"}}
			} else {
				old["spec"].(map[string]any)[field] = map[string]any{"service": map[string]any{"name": "fallback", "port": map[string]any{"number": 8080}}}
			}
			r := &publicationRunner{ingresses: map[string]resource{"old": old}}
			m, _ := New(config(t), r)
			if err := m.Publish(context.Background(), "app.example.com", "first", "app", 8080); err == nil || len(r.routes) != 0 {
				t.Fatal("discarded customized legacy routing")
			}
		})
	}
}
