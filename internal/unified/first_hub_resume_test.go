package unified

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"tailscale.com/types/key"
)

func firstHubResumeFixture(t *testing.T) (*installation, *coordinator.Server, *coordinator.MemoryStore, string) {
	t.Helper()
	i := testInstallation(t.TempDir())
	i.Phase = "ready"
	i.PodRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.1.0/24")}
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, node, err := seedState(id, i)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(node.PodRoutes, i.PodRoutes) || !slices.Equal(snapshot.PodRoutes, i.PodRoutes) {
		t.Fatal("seed lost Kubernetes route provenance")
	}
	store := &coordinator.MemoryStore{}
	srv, err := coordinator.New(context.Background(), coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	err = srv.Update(context.Background(), func(s *coordinator.State) error {
		if err := coordinator.AllocateNode(s, node); err != nil {
			return err
		}
		r := enrollment.Registry{Cluster: enrollment.Cluster{ID: i.ClusterID, HostCIDR: i.Config.HostCIDR, PodCIDR: i.Config.PodCIDR, ServiceCIDR: i.Config.ServiceCIDR}, Invites: map[string]*enrollment.Invite{}, Members: map[string]*enrollment.Member{node.MachineKey: {Name: node.Hostname, Role: "hub", Voter: true, Ready: true}}}
		if err := enrollment.WriteRegistry(s, r); err != nil {
			return err
		}
		return storeServices(s, cluster.ServiceConfig{PublicURL: i.Services.PublicURL, Image: "registry.example.com/connect:current"})
	})
	if err != nil {
		t.Fatal(err)
	}
	return i, srv, store, node.MachineKey
}

func TestFirstHubResumeReplacesPodAllocationAcrossConcurrentStateChange(t *testing.T) {
	i, srv, store, machine := firstHubResumeFixture(t)
	ctx := context.Background()
	before, _ := store.Load(ctx)
	original := *before.Nodes[machine]
	oldPod := i.PodRoutes[0]
	newPod := netip.MustParsePrefix("10.42.3.0/24")
	manual := netip.MustParsePrefix("192.168.80.0/24")
	i.PodRoutes = []netip.Prefix{newPod}
	attempts := 0
	update := func(ctx context.Context, mutate func(*coordinator.State) error) error {
		return srv.Update(ctx, func(s *coordinator.State) error {
			if err := mutate(s); err != nil {
				return err
			}
			attempts++
			if attempts == 1 {
				// Another hub publishes while the first hub is replacing its pod
				// allocation. The retry must retain that update and read it anew.
				return srv.Update(ctx, func(current *coordinator.State) error {
					current.Nodes[machine].ApprovedRoutes = append(current.Nodes[machine].ApprovedRoutes, manual)
					return storeServices(current, cluster.ServiceConfig{PublicURL: i.Services.PublicURL, Image: "registry.example.com/connect:new"})
				})
			}
			return nil
		})
	}
	if err := refreshFirstHubRegistration(ctx, i, update); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("expected one CAS retry, got %d attempts", attempts)
	}
	after, _ := store.Load(ctx)
	n := after.Nodes[machine]
	if !slices.Equal(n.PodRoutes, []netip.Prefix{newPod}) || !slices.Contains(n.ApprovedRoutes, newPod) || slices.Contains(n.ApprovedRoutes, oldPod) || !slices.Contains(n.ApprovedRoutes, manual) || !slices.Contains(n.ApprovedRoutes, netip.MustParsePrefix(i.Config.PodCIDR)) {
		t.Fatalf("resume did not preserve independent approvals: %v, managed %v", n.ApprovedRoutes, n.PodRoutes)
	}
	if n.ID != original.ID || n.NodeKey != original.NodeKey || n.DiscoKey != original.DiscoKey || !slices.Equal(n.Addresses, original.Addresses) {
		t.Fatal("resume changed existing identity")
	}
	if i.Services.Image != "registry.example.com/connect:new" {
		t.Fatal("resume kept stale service configuration")
	}
}

func TestFirstHubResumeRejectsIdentityDriftBeforeRouteApproval(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*coordinator.State, string)
	}{
		{"revoked", func(s *coordinator.State, machine string) { s.Nodes[machine].Revoked = true }},
		{"replaced-key", func(s *coordinator.State, machine string) { s.Nodes[machine].NodeKey = key.NewNode().Public().String() }},
		{"reallocated-address", func(s *coordinator.State, machine string) {
			s.Nodes[machine].Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.8/32")}
		}},
		{"missing-membership", func(s *coordinator.State, machine string) {
			r, _ := enrollment.ReadRegistry(s)
			delete(r.Members, machine)
			_ = enrollment.WriteRegistry(s, r)
		}},
		{"different-cluster", func(s *coordinator.State, _ string) {
			r, _ := enrollment.ReadRegistry(s)
			r.Cluster.ID = "other-cluster"
			_ = enrollment.WriteRegistry(s, r)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			i, srv, store, machine := firstHubResumeFixture(t)
			ctx := context.Background()
			if err := srv.Update(ctx, func(s *coordinator.State) error { test.change(s, machine); return nil }); err != nil {
				t.Fatal(err)
			}
			before, _ := store.Load(ctx)
			i.PodRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.4.0/24")}
			if err := refreshFirstHubRegistration(ctx, i, srv.Update); err == nil {
				t.Fatal("mismatched membership authorized local route replacement")
			}
			after, _ := store.Load(ctx)
			if before.Revision != after.Revision || !slices.Equal(before.Nodes[machine].ApprovedRoutes, after.Nodes[machine].ApprovedRoutes) {
				t.Fatal("failed identity validation committed route changes")
			}
		})
	}
}
