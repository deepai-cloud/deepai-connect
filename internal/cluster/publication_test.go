package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

type publicationRunner struct {
	servicesAPIRunner
	publicationMu sync.Mutex
	ingresses     map[string]resource
}

func (r *publicationRunner) Run(ctx context.Context, body []byte, command string, args ...string) ([]byte, error) {
	if slices.Contains(args, "get") && slices.Contains(args, "service") {
		return []byte(`{"spec":{"ports":[{"port":8080,"protocol":"TCP"}]}}`), nil
	}
	list := slices.Contains(args, "get") && slices.Contains(args, "ingress")
	apply := slices.Contains(args, "apply")
	if !list && !apply {
		return r.servicesAPIRunner.Run(ctx, body, command, args...)
	}
	r.mu.Lock()
	held := r.lease != nil && r.lease.Spec.HolderIdentity != ""
	r.mu.Unlock()
	if !held {
		return nil, errors.New("publication checked or changed without the cluster lease")
	}
	r.publicationMu.Lock()
	defer r.publicationMu.Unlock()
	if list {
		items := []resource{}
		for _, ingress := range r.ingresses {
			items = append(items, ingress)
		}
		return json.Marshal(resource{"items": items})
	}
	var ingress resource
	if err := json.Unmarshal(body, &ingress); err != nil {
		return nil, err
	}
	meta := ingress["metadata"].(map[string]any)
	r.ingresses[meta["namespace"].(string)+"/"+meta["name"].(string)] = ingress
	return nil, nil
}

func TestPublicationUpdatesOwnedRouteAndRejectsNamespaceCollision(t *testing.T) {
	r := &publicationRunner{ingresses: map[string]resource{}}
	m, err := New(config(t), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"original", "replacement"} {
		if err := m.Publish(context.Background(), "app.example.com", "first", service, 8080); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.ingresses) != 1 {
		t.Fatal("same-namespace publication created another route")
	}
	for _, ingress := range r.ingresses {
		spec := ingress["spec"].(map[string]any)
		rule := spec["rules"].([]any)[0].(map[string]any)
		path := rule["http"].(map[string]any)["paths"].([]any)[0].(map[string]any)
		backend := path["backend"].(map[string]any)["service"].(map[string]any)
		if spec["ingressClassName"] != "traefik" || backend["name"] != "replacement" {
			t.Fatal("publication did not update the managed backend")
		}
	}
	before, _ := json.Marshal(r.ingresses)
	if err := m.Publish(context.Background(), "app.example.com", "second", "different", 8080); err == nil {
		t.Fatal("published competing hostname in another namespace")
	}
	after, _ := json.Marshal(r.ingresses)
	if string(before) != string(after) {
		t.Fatal("rejected publication changed existing routes")
	}
	for _, ingress := range r.ingresses {
		ingress["metadata"].(map[string]any)["labels"] = map[string]any{"app.kubernetes.io/part-of": "other"}
	}
	if err := m.Publish(context.Background(), "app.example.com", "first", "different", 8080); err == nil {
		t.Fatal("publication overwrote an Ingress owned by another application")
	}
}

func TestConcurrentPublishersCannotClaimHostnameInDifferentNamespaces(t *testing.T) {
	r := &publicationRunner{ingresses: map[string]resource{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start, results := make(chan struct{}), make(chan error, 2)
	for _, namespace := range []string{"first", "second"} {
		m, err := New(config(t), r)
		if err != nil {
			t.Fatal(err)
		}
		m.Config.Name = namespace
		go func() {
			<-start
			results <- m.Publish(ctx, "app.example.com", namespace, "app", 8080)
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 || len(r.ingresses) != 1 {
		t.Fatalf("competing publication claims: successes=%d routes=%d", successes, len(r.ingresses))
	}
}
