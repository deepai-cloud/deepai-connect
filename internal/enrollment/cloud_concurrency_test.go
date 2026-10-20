package enrollment

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"tailscale.com/tailcfg"
)

func TestNamedClaimRevalidatesDeclarationAfterConcurrentApply(t *testing.T) {
	for name, change := range map[string]func(*cloudconfig.Cloud){
		"removed": func(c *cloudconfig.Cloud) { delete(c.Nodes, "hub-second") },
		"role":    func(c *cloudconfig.Cloud) { c.Nodes["hub-second"] = cloudconfig.Node{Role: "worker"} },
		"voter": func(c *cloudconfig.Cloud) {
			node := c.Nodes["hub-second"]
			node.Voter = true
			c.Nodes["hub-second"] = node
		},
		"public-ip": func(c *cloudconfig.Cloud) {
			node := c.Nodes["hub-second"]
			node.PublicIP = "203.0.113.21"
			c.Nodes["hub-second"] = node
		},
		"relay-domain": func(c *cloudconfig.Cloud) {
			node := c.Nodes["hub-second"]
			node.RelayDomain = "replacement-relay.example.com"
			c.Nodes["hub-second"] = node
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			b, srv, backend := fixture(t)
			spec := declaredCloud()
			applyDeclaredCloud(t, b, spec, nil)
			inv, err := b.InviteNode(ctx, "hub-second", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			node, signer := identity("hub-second")
			node.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")}
			before, err := b.Store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			change(spec)
			var once sync.Once
			var applyErr error
			var revision string
			backend.healthy = func() error {
				once.Do(func() {
					// Commit a different declaration after the claim has read
					// and authorized its invitation but before its CAS.
					applyErr = srv.Update(ctx, func(s *coordinator.State) error {
						var err error
						revision, err = ApplyCloud(s, spec, []tailcfg.FilterRule{})
						return err
					})
				})
				return applyErr
			}
			if _, err := b.enroll(ctx, request(node, signer, "enroll"), inv.Token); !errors.Is(err, coordinator.ErrUnauthorized) {
				t.Fatalf("stale named invitation was not rejected after CAS conflict: %v", err)
			}
			if applyErr != nil || revision == "" {
				t.Fatalf("concurrent apply did not commit: %v", applyErr)
			}
			after, err := b.Store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := ReadRegistry(after)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before.Nodes, after.Nodes) || before.NextID != after.NextID ||
				registry.Invites[coordinator.TokenHash(inv.Token)].Machine != "" || registry.PendingVoter != "" {
				t.Fatal("failed stale claim partially committed membership or consumed its invitation")
			}
			if registry.Cloud.Revision != revision || !reflect.DeepEqual(registry.Cloud.Spec, *spec) || after.Policy == nil || len(after.Policy) != 0 {
				t.Fatal("failed stale claim overwrote concurrent configuration or packet policy")
			}
		})
	}
}

func TestIndependentBrokersCannotAssignOneDeclaredNameTwice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, _, backend := fixture(t)
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	// Use distinct coordinator instances and a shared transactional store, as
	// independent replicas do; a process-local lock cannot make this test pass.
	replica, err := coordinator.New(ctx, coordinator.Config{Store: b.Store})
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	second := &Broker{Store: b.Store, Update: replica.Update, Backend: backend}
	firstInvitation, err := b.InviteNode(ctx, "my-worker", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secondInvitation, err := second.InviteNode(ctx, "my-worker", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, err := b.Store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	backend.healthy = func() error {
		if calls.Add(1) <= 2 {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	type attempt struct {
		broker *Broker
		invite Invitation
		req    Request
		grant  Grant
		err    error
	}
	results := make(chan attempt, 2)
	for i, inv := range []Invitation{firstInvitation, secondInvitation} {
		node, signer := identity("my-worker")
		broker := []*Broker{b, second}[i]
		req := request(node, signer, "enroll")
		go func() {
			grant, err := broker.enroll(ctx, req, inv.Token)
			results <- attempt{broker: broker, invite: inv, req: req, grant: grant, err: err}
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-ctx.Done():
			close(release)
			t.Fatal("both replicas did not reach the concurrent claim barrier")
		}
	}
	close(release)
	var winner attempt
	successes := 0
	for range 2 {
		select {
		case result := <-results:
			if result.err == nil {
				winner = result
				successes++
			}
		case <-ctx.Done():
			t.Fatal("concurrent claim did not finish")
		}
	}
	if successes != 1 {
		t.Fatalf("two invitations for one name enrolled %d identities", successes)
	}
	state, err := b.Store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := ReadRegistry(state)
	if err != nil {
		t.Fatal(err)
	}
	consumed := 0
	for _, inv := range registry.Invites {
		if inv.Machine != "" {
			consumed++
			if inv.Machine != winner.req.Node.MachineKey {
				t.Fatal("invitation consumed by a losing identity")
			}
		}
	}
	if consumed != 1 || len(registry.Members) != 2 || len(state.Nodes) != 2 || state.NextID != before.NextID+1 || backend.tokens.Load() != 0 {
		t.Fatal("concurrent claims leaked an allocation, consumed extra capabilities or released credentials")
	}
	resumed, err := winner.broker.enroll(ctx, winner.req, winner.invite.Token)
	if err != nil || resumed.Self.ID != winner.grant.Self.ID || !reflect.DeepEqual(resumed.Self.Addresses, winner.grant.Self.Addresses) {
		t.Fatalf("winning identity could not recover its persisted grant: %v", err)
	}
}

func TestFailedNamedClaimLeavesCapabilityAndAllocationReusable(t *testing.T) {
	ctx := context.Background()
	b, _, backend := fixture(t)
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	inv, err := b.InviteNode(ctx, "my-worker", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, signer := identity("my-worker")
	before, err := b.Store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// This check runs after AllocateNode and must roll back the whole claim.
	backend.validate = func(coordinator.Node, bool, bool) error { return errors.New("Kubernetes lookup failed") }
	if _, err := b.enroll(ctx, request(node, signer, "enroll"), inv.Token); err == nil {
		t.Fatal("failed validation admitted member")
	}
	after, err := b.Store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("failed validation partially persisted the claim: %v", err)
	}
	backend.validate = nil
	retried, err := b.enroll(ctx, request(node, signer, "enroll"), inv.Token)
	if err != nil || uint64(retried.Self.ID) != before.NextID {
		t.Fatalf("failed claim lost its invitation or next available node identity: %v", err)
	}
}
