package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

type servicesAPIRunner struct {
	mu                sync.Mutex
	lease             *servicesLease
	revision          int
	desired           ServiceConfig
	applied           []string
	inApply, maxApply int
	firstApply        chan struct{}
	releaseFirst      chan struct{}
	deny              bool
}

func (r *servicesAPIRunner) Run(ctx context.Context, input []byte, _ string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deny {
		return nil, errors.New("Kubernetes permission denied")
	}
	if slices.Contains(args, "get") && slices.Contains(args, "--raw") {
		if slices.Contains(args, hubNodesPath) {
			return []byte(gatewayHubNodes), nil
		}
		if slices.Contains(args, traefikConfigPath) {
			return []byte(gatewayChart), nil
		}
		return []byte(packagedDeployment), nil
	}
	if slices.Contains(args, "get") && slices.Contains(args, "helmchartconfig") {
		return []byte(gatewayChart), nil
	}
	if slices.Contains(args, "get") && slices.Contains(args, "gateway") {
		return []byte(readyGateway), nil
	}
	if slices.Contains(args, "get") && slices.Contains(args, "lease") {
		if r.lease == nil {
			return nil, nil
		}
		return json.Marshal(r.lease)
	}
	if slices.Contains(args, "get") && slices.Contains(args, "networkstate") {
		return json.Marshal(map[string]any{"spec": map[string]any{"extensions": map[string]any{serviceRegistryExtension: r.desired}}})
	}
	if slices.Contains(args, "create") || slices.Contains(args, "replace") {
		var next servicesLease
		if err := json.Unmarshal(input, &next); err != nil {
			return nil, err
		}
		if next.Kind != "Lease" {
			return nil, errors.New("unexpected write")
		}
		if slices.Contains(args, "create") && r.lease != nil {
			return nil, errors.New("already exists")
		}
		if slices.Contains(args, "replace") && (r.lease == nil || next.Metadata.ResourceVersion != r.lease.Metadata.ResourceVersion) {
			return nil, errors.New("resource version conflict")
		}
		r.revision++
		next.Metadata.ResourceVersion = fmt.Sprint(r.revision)
		r.lease = &next
		return json.Marshal(&next)
	}
	if slices.Contains(args, "apply") {
		var manifest struct {
			Items []struct {
				Kind     string
				Metadata struct{ Name string }
				Spec     struct {
					Template struct {
						Spec struct{ Containers []struct{ Image string } }
					}
				}
			}
		}
		if err := json.Unmarshal(input, &manifest); err != nil {
			return nil, err
		}
		for _, item := range manifest.Items {
			if item.Kind == "Deployment" && item.Metadata.Name == "connect-coordinator" {
				r.applied = append(r.applied, item.Spec.Template.Spec.Containers[0].Image)
			}
		}
		r.inApply++
		r.maxApply = max(r.maxApply, r.inApply)
		if len(r.applied) == 1 && r.firstApply != nil {
			close(r.firstApply)
			wait := r.releaseFirst
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				r.mu.Lock()
				r.inApply--
				return nil, ctx.Err()
			case <-wait:
			}
			r.mu.Lock()
		}
		r.inApply--
		return nil, nil
	}
	return nil, nil
}

func TestRegisteredServicesSerializeAndReloadAfterLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := &servicesAPIRunner{desired: services(), firstApply: make(chan struct{}), releaseFirst: make(chan struct{})}
	a, err := New(config(t), r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(config(t), r)
	if err != nil {
		t.Fatal(err)
	}
	b.Config.Name = "hub-two"
	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	go func() { doneA <- a.ApplyRegisteredServices(ctx) }()
	select {
	case <-r.firstApply:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r.mu.Lock()
	r.desired.Image = "registry.example.com/connect:v2.0.0"
	r.mu.Unlock()
	go func() { doneB <- b.ApplyRegisteredServices(ctx) }()
	// The second operation cannot take ownership while the first is alive.
	select {
	case err := <-doneB:
		t.Fatalf("second reconciler bypassed active lease: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(r.releaseFirst)
	for _, done := range []chan error{doneA, doneB} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxApply != 1 || len(r.applied) != 2 || r.applied[1] != "registry.example.com/connect:v2.0.0" {
		t.Fatalf("concurrent or stale application: active=%d images=%v", r.maxApply, r.applied)
	}
	if r.lease.Spec.HolderIdentity != "" {
		t.Fatal("lease not released")
	}
}

func TestServiceLeaseFailsClosedAndRecoversExpiration(t *testing.T) {
	r := &servicesAPIRunner{desired: services()}
	m, err := New(config(t), r)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = m.acquireServicesLease(ctx, "original"); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if err = m.acquireServicesLease(bounded, "contender"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("active lease stolen: %v", err)
	}
	r.mu.Lock()
	past := time.Now().Add(-2 * time.Minute)
	r.lease.Spec.RenewTime = &leaseTime{past}
	r.mu.Unlock()
	if err = m.acquireServicesLease(ctx, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err = m.renewServicesLease(ctx, "original"); err == nil {
		t.Fatal("former holder renewed a lease it no longer owns")
	}
	if err = m.releaseServicesLease("original"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	owner := r.lease.Spec.HolderIdentity
	r.mu.Unlock()
	if owner != "replacement" {
		t.Fatal("former holder cleared replacement lease")
	}
	if err = m.renewServicesLease(ctx, "replacement"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.deny = true
	r.mu.Unlock()
	if err = m.ApplyRegisteredServices(ctx); err == nil {
		t.Fatal("reconciled despite missing lease authorization")
	}
}

func TestServiceLeaseTimestampMatchesKubernetesMicroTime(t *testing.T) {
	for _, nanos := range []int{0, 123456789, 123450000} {
		stamp := leaseTime{time.Date(2026, 10, 15, 18, 16, 0, nanos, time.UTC)}
		lease := servicesLease{}
		lease.Spec.AcquireTime = &stamp
		lease.Spec.RenewTime = &stamp
		encoded, err := json.Marshal(lease)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Spec struct{ AcquireTime, RenewTime string }
		}
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{wire.Spec.AcquireTime, wire.Spec.RenewTime} {
			parsed, err := time.Parse("2006-01-02T15:04:05.000000Z07:00", value)
			if err != nil || !parsed.Equal(stamp.Truncate(time.Microsecond)) {
				t.Fatalf("timestamp rejected by Kubernetes MicroTime decoder: %q: %v", value, err)
			}
		}
		var decoded servicesLease
		if err := json.Unmarshal(encoded, &decoded); err != nil || !decoded.Spec.RenewTime.Equal(stamp.Truncate(time.Microsecond)) {
			t.Fatalf("lease timestamp failed round trip: %v", err)
		}
	}
}
