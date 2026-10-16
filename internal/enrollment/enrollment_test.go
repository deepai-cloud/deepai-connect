package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type testBackend struct {
	tokens       atomic.Int32
	serverTokens atomic.Int32
	probe        func() error
	healthy      func() error
	validate     func(coordinator.Node, bool, bool) error
	podRoutes    func() ([]netip.Prefix, error)
}

func (b *testBackend) Healthy(context.Context, []string) error {
	if b.healthy != nil {
		return b.healthy()
	}
	return nil
}
func (b *testBackend) Token(_ context.Context, server bool) (string, error) {
	b.tokens.Add(1)
	if server {
		b.serverTokens.Add(1)
		return "K10" + strings.Repeat("a", 64) + "::server:private", nil
	}
	return "K10" + strings.Repeat("a", 64) + "::abcdef.0123456789abcdef", nil
}
func (b *testBackend) PodRoutes(context.Context, string) ([]netip.Prefix, error) {
	if b.podRoutes != nil {
		return b.podRoutes()
	}
	return []netip.Prefix{netip.MustParsePrefix("10.42.1.0/24")}, nil
}
func (b *testBackend) ValidateNode(_ context.Context, n coordinator.Node, voter, ready bool) error {
	if b.validate != nil {
		return b.validate(n, voter, ready)
	}
	return nil
}
func (b *testBackend) Probe(context.Context, netip.Addr, ed25519.PublicKey) error {
	if b.probe != nil {
		return b.probe()
	}
	return nil
}
func identity(name string) (coordinator.Node, ed25519.PrivateKey) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	return coordinator.Node{MachineKey: key.NewMachine().Public().String(), NodeKey: key.NewNode().Public().String(), DiscoKey: key.NewDisco().Public().String(), Hostname: name, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:41641")}}, ed
}
func fixture(t *testing.T) (*Broker, *coordinator.Server, *testBackend) {
	t.Helper()
	ctx := context.Background()
	store := &coordinator.MemoryStore{}
	srv, err := coordinator.New(ctx, coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	hub, _ := identity("hub-initial")
	hub.Role = "hub"
	err = srv.Update(ctx, func(s *coordinator.State) error {
		if err := coordinator.AllocateNode(s, &hub); err != nil {
			return err
		}
		return WriteRegistry(s, Registry{Cluster: Cluster{ID: "cluster-id", URL: "https://mesh.example.com", HostCIDR: "100.64.0.0/10", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", DesiredVoters: 3, Image: "connect:v1"}, Invites: map[string]*Invite{}, Members: map[string]*Member{hub.MachineKey: {Name: hub.Hostname, Role: "hub", Voter: true, Ready: true}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{}
	return &Broker{Store: store, Update: srv.Update, Backend: backend}, srv, backend
}
func request(n coordinator.Node, k ed25519.PrivateKey, action string) Request {
	return Sign(Request{ClusterID: "cluster-id", Action: action, Node: n, Issued: time.Now().UTC()}, k)
}
func enrollOne(t *testing.T, b *Broker, role string, voter bool) (Request, Grant, Invitation) {
	t.Helper()
	inv, err := b.Invite(context.Background(), role, voter, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n, k := identity("joining-host")
	req := request(n, k, "enroll")
	g, err := b.enroll(context.Background(), req, inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	return req, g, inv
}
func TestConcurrentInvitationClaimIsSingleUse(t *testing.T) {
	b, _, _ := fixture(t)
	inv, err := b.Invite(context.Background(), "worker", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, name := range []string{"worker-one", "worker-two"} {
		n, k := identity(name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := b.enroll(context.Background(), request(n, k, "enroll"), inv.Token); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("invitation granted %d devices", successes.Load())
	}
	s, err := b.Store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes) != 2 {
		t.Fatal("failed claim leaked a node allocation")
	}
}
func TestEnrollmentResumesOnlyForOriginalSignedIdentity(t *testing.T) {
	b, _, backend := fixture(t)
	req, g, inv := enrollOne(t, b, "worker", false)
	resumed, err := b.enroll(context.Background(), req, inv.Token)
	if err != nil || resumed.Self.ID != g.Self.ID {
		t.Fatal("resuming invitation allocated a new identity")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := Sign(req, other)
	if _, err = b.enroll(context.Background(), forged, inv.Token); err == nil {
		t.Fatal("consumed invitation accepted different signer")
	}
	if g.Token != "" || backend.tokens.Load() != 0 {
		t.Fatal("cluster credential released before connectivity verification")
	}
	grant, err := b.confirm(context.Background(), req, false)
	if err != nil {
		t.Fatal(err)
	}
	if backend.serverTokens.Load() != 0 || !strings.HasSuffix(grant.Token, "::abcdef.0123456789abcdef") {
		t.Fatal("worker received a server credential")
	}
}
func TestVoterJoinsAreSerializedUntilVerifiedCompletion(t *testing.T) {
	b, _, backend := fixture(t)
	inv1, _ := b.Invite(context.Background(), "hub", true, time.Hour)
	inv2, _ := b.Invite(context.Background(), "hub", true, time.Hour)
	n1, k1 := identity("hub-second")
	n2, k2 := identity("hub-third")
	r1, r2 := request(n1, k1, "enroll"), request(n2, k2, "enroll")
	if _, err := b.enroll(context.Background(), r1, inv1.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := b.enroll(context.Background(), r2, inv2.Token); err == nil {
		t.Fatal("second concurrent etcd join admitted")
	}
	backend.validate = func(_ coordinator.Node, _ bool, ready bool) error {
		if ready {
			return errors.New("not ready")
		}
		return nil
	}
	if _, err := b.confirm(context.Background(), r1, true); err == nil {
		t.Fatal("incomplete voter released the reservation")
	}
	backend.validate = nil
	if _, err := b.confirm(context.Background(), r1, true); err != nil {
		t.Fatal(err)
	}
	if _, err := b.enroll(context.Background(), r2, inv2.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := b.confirm(context.Background(), r2, false); err != nil {
		t.Fatal(err)
	}
	if backend.serverTokens.Load() != 1 {
		t.Fatal("hub did not receive server credential after verification")
	}
}
func TestPendingVoterPreventsConcurrentClaimsAcrossReplicas(t *testing.T) {
	b, srv, _ := fixture(t)
	replica := &Broker{Store: b.Store, Update: srv.Update, Backend: &testBackend{}}
	inv1, _ := b.Invite(context.Background(), "hub", true, time.Hour)
	inv2, _ := b.Invite(context.Background(), "hub", true, time.Hour)
	var wg sync.WaitGroup
	var winners atomic.Int32
	start := make(chan struct{})
	for j, inv := range []Invitation{inv1, inv2} {
		n, k := identity([]string{"hub-a", "hub-b"}[j])
		broker := []*Broker{b, replica}[j]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := broker.enroll(context.Background(), request(n, k, "enroll"), inv.Token); err == nil {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("admitted %d voters concurrently", winners.Load())
	}
}
func TestRevocationDuringProbePreventsCredentialRelease(t *testing.T) {
	b, srv, backend := fixture(t)
	req, _, _ := enrollOne(t, b, "hub", true)
	backend.probe = func() error {
		return srv.Update(context.Background(), func(s *coordinator.State) error { s.Nodes[req.Node.MachineKey].Revoked = true; return nil })
	}
	if _, err := b.confirm(context.Background(), req, false); err == nil {
		t.Fatal("revoked device received cluster credentials")
	}
	if backend.tokens.Load() != 0 {
		t.Fatal("token backend called after revocation")
	}
}
func TestRevocationDuringHealthCheckPreventsCredentialRelease(t *testing.T) {
	b, srv, backend := fixture(t)
	req, _, _ := enrollOne(t, b, "worker", false)
	var once sync.Once
	backend.healthy = func() error {
		var err error
		once.Do(func() {
			err = srv.Update(context.Background(), func(s *coordinator.State) error { s.Nodes[req.Node.MachineKey].Revoked = true; return nil })
		})
		return err
	}
	if _, err := b.confirm(context.Background(), req, false); err == nil {
		t.Fatal("revocation during readiness check was lost")
	}
	if backend.tokens.Load() != 0 {
		t.Fatal("token released after failed authorization fence")
	}
}
func TestRevocationDuringCompletionRetainsVoterReservation(t *testing.T) {
	b, srv, backend := fixture(t)
	req, _, _ := enrollOne(t, b, "hub", true)
	backend.validate = func(_ coordinator.Node, _ bool, ready bool) error {
		if ready {
			return srv.Update(context.Background(), func(s *coordinator.State) error { s.Nodes[req.Node.MachineKey].Revoked = true; return nil })
		}
		return nil
	}
	if _, err := b.confirm(context.Background(), req, true); err == nil {
		t.Fatal("completed revoked voter")
	}
	s, _ := b.Store.Load(context.Background())
	r, _ := ReadRegistry(s)
	if r.PendingVoter != req.Node.MachineKey || r.Members[req.Node.MachineKey].Ready {
		t.Fatal("revoked/incomplete member released sequential admission")
	}
}
func TestStaleKubernetesNodeCannotBeAdoptedByEnrollment(t *testing.T) {
	b, _, backend := fixture(t)
	backend.validate = func(_ coordinator.Node, _ bool, _ bool) error { return errors.New("node name already registered") }
	inv, _ := b.Invite(context.Background(), "worker", false, time.Hour)
	n, k := identity("existing-name")
	if _, err := b.enroll(context.Background(), request(n, k, "enroll"), inv.Token); err == nil {
		t.Fatal("silently adopted stale Kubernetes identity")
	}
	s, _ := b.Store.Load(context.Background())
	if len(s.Nodes) != 1 {
		t.Fatal("rejected node claim committed network membership")
	}
}
func TestHandlerAuthenticatesSignedBodyAndAction(t *testing.T) {
	b, _, _ := fixture(t)
	inv, _ := b.Invite(context.Background(), "worker", false, time.Hour)
	n, k := identity("signed-worker")
	tests := []struct {
		name  string
		alter func(*Request)
		path  string
		want  int
	}{{"tamper", func(r *Request) { r.Node.Hostname = "tampered" }, "/v1/enroll", 400}, {"expired", func(r *Request) { r.Issued = time.Now().Add(-6 * time.Minute); *r = Sign(*r, k) }, "/v1/enroll", 400}, {"future", func(r *Request) { r.Issued = time.Now().Add(2 * time.Minute); *r = Sign(*r, k) }, "/v1/enroll", 400}, {"action-mismatch", func(r *Request) {}, "/v1/complete", 404}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := request(n, k, "enroll")
			tt.alter(&signed)
			body, _ := json.Marshal(signed)
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+inv.Token)
			w := httptest.NewRecorder()
			b.Handler().ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("got HTTP %d want %d", w.Code, tt.want)
			}
		})
	}
}

func TestCompletionApprovesOnlyKubernetesAssignedPodRoutes(t *testing.T) {
	b, srv, backend := fixture(t)
	req, _, _ := enrollOne(t, b, "worker", false)
	ctx := context.Background()
	oldPod := netip.MustParsePrefix("10.42.1.0/24")
	newPod := netip.MustParsePrefix("10.42.2.0/24")
	manual := netip.MustParsePrefix("192.168.70.0/24")
	if err := srv.Update(ctx, func(s *coordinator.State) error {
		s.Nodes[req.Node.MachineKey].ApprovedRoutes = []netip.Prefix{manual}
		// A hub's aggregate gateway approval must not block specific node CIDRs.
		for machine, node := range s.Nodes {
			if machine != req.Node.MachineKey {
				node.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Client-supplied approvals are never used as the Kubernetes allocation.
	req.Node.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	req.Node.PodRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.255.0/24")}
	if _, err := b.confirm(ctx, req, true); err != nil {
		t.Fatal(err)
	}
	s, _ := b.Store.Load(ctx)
	n := s.Nodes[req.Node.MachineKey]
	if !slices.Equal(n.PodRoutes, []netip.Prefix{oldPod}) || !slices.Equal(n.ApprovedRoutes, []netip.Prefix{manual, oldPod}) {
		t.Fatalf("completion did not approve API allocation: %#v", n)
	}
	backend.podRoutes = func() ([]netip.Prefix, error) { return []netip.Prefix{newPod}, nil }
	for range 2 {
		if _, err := b.confirm(ctx, req, true); err != nil {
			t.Fatal(err)
		}
	}
	s, _ = b.Store.Load(ctx)
	n = s.Nodes[req.Node.MachineKey]
	if !slices.Equal(n.PodRoutes, []netip.Prefix{newPod}) || !slices.Equal(n.ApprovedRoutes, []netip.Prefix{manual, newPod}) {
		t.Fatalf("allocation refresh changed unrelated approvals or duplicated routes: %#v", n)
	}
}

func TestInvalidPodAllocationCannotCompleteVoter(t *testing.T) {
	for name, routes := range map[string][]netip.Prefix{
		"missing":   nil,
		"default":   {netip.MustParsePrefix("0.0.0.0/0")},
		"service":   {netip.MustParsePrefix("10.43.1.0/24")},
		"host":      {netip.MustParsePrefix("100.64.0.0/24")},
		"unmasked":  {netip.MustParsePrefix("10.42.1.5/24")},
		"duplicate": {netip.MustParsePrefix("10.42.1.0/24"), netip.MustParsePrefix("10.42.1.0/25")},
		"invalid":   {{}},
	} {
		t.Run(name, func(t *testing.T) {
			b, _, backend := fixture(t)
			req, _, _ := enrollOne(t, b, "hub", true)
			backend.podRoutes = func() ([]netip.Prefix, error) { return routes, nil }
			if _, err := b.confirm(context.Background(), req, true); err == nil {
				t.Fatal("untrusted allocation marked node ready")
			}
			s, _ := b.Store.Load(context.Background())
			r, _ := ReadRegistry(s)
			if r.PendingVoter != req.Node.MachineKey || r.Members[req.Node.MachineKey].Ready || len(s.Nodes[req.Node.MachineKey].ApprovedRoutes) != 0 {
				t.Fatal("invalid allocation partially committed enrollment")
			}
		})
	}
}

func TestPodRouteOwnershipAndRevocationDuringLookup(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "already-owned"
		if revoke {
			name = "revoked-during-lookup"
		}
		t.Run(name, func(t *testing.T) {
			b, srv, backend := fixture(t)
			req, _, _ := enrollOne(t, b, "worker", false)
			route := netip.MustParsePrefix("10.42.1.0/24")
			backend.podRoutes = func() ([]netip.Prefix, error) {
				err := srv.Update(context.Background(), func(s *coordinator.State) error {
					if revoke {
						s.Nodes[req.Node.MachineKey].Revoked = true
					} else {
						for machine, n := range s.Nodes {
							if machine != req.Node.MachineKey {
								n.PodRoutes = []netip.Prefix{route}
								n.ApprovedRoutes = []netip.Prefix{route}
							}
						}
					}
					return nil
				})
				return []netip.Prefix{route}, err
			}
			if _, err := b.confirm(context.Background(), req, true); err == nil {
				t.Fatal("stale authorization approved pod traffic")
			}
			s, _ := b.Store.Load(context.Background())
			r, _ := ReadRegistry(s)
			if r.Members[req.Node.MachineKey].Ready || len(s.Nodes[req.Node.MachineKey].PodRoutes) != 0 {
				t.Fatal("failed completion committed allocation")
			}
		})
	}
}

func TestBootstrapGrantIncludesPodReturnRoutesAndExcludesExpiredPeers(t *testing.T) {
	b, srv, _ := fixture(t)
	ctx := context.Background()
	pod := netip.MustParsePrefix("10.42.0.0/24")
	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	extraSubnet := netip.MustParsePrefix("192.168.50.0/24")
	expired, _ := identity("expired-native-client")
	expired.Role = "client"
	expired.KeyExpiry = time.Now().Add(-time.Minute)
	if err := srv.Update(ctx, func(s *coordinator.State) error {
		for _, hub := range s.Nodes {
			hub.ApprovedRoutes = []netip.Prefix{pod, defaultRoute, extraSubnet}
			hub.PodRoutes = []netip.Prefix{pod}
			hub.Hostinfo = &tailcfg.Hostinfo{Hostname: hub.Hostname, RoutableIPs: []netip.Prefix{pod, defaultRoute, extraSubnet}}
		}
		return coordinator.AllocateNode(s, &expired)
	}); err != nil {
		t.Fatal(err)
	}
	req, grant, _ := enrollOne(t, b, "hub", false)
	if len(grant.Peers) != 1 || !slices.Contains(grant.Peers[0].AllowedIPs, pod) {
		t.Fatalf("bootstrap lacks pod-to-joining-host return path or includes expired peer: %+v", grant.Peers)
	}
	if slices.Contains(grant.Peers[0].AllowedIPs, defaultRoute) || slices.Contains(grant.Peers[0].AllowedIPs, extraSubnet) || slices.Contains(grant.Peers[0].PrimaryRoutes, defaultRoute) {
		t.Fatal("bootstrap grant enabled gateway or additional routes before local opt-in")
	}
	if len(grant.ServerURLs) != 1 || grant.ServerURLs[0] == "https://"+grant.Self.Addresses[0].Addr().String()+":6443" {
		t.Fatal("incomplete hub was advertised as an available Kubernetes server")
	}
	if err := srv.Update(ctx, func(s *coordinator.State) error {
		s.Nodes[req.Node.MachineKey].KeyExpiry = time.Now().Add(-time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.confirm(ctx, req, false); err == nil {
		t.Fatal("expired joining identity received a credential")
	}
}

func TestConsumedInvitationCanResumeAfterExpiryOnlyForOriginalIdentity(t *testing.T) {
	b, srv, _ := fixture(t)
	req, grant, inv := enrollOne(t, b, "worker", false)
	ctx := context.Background()
	unused, err := b.Invite(ctx, "worker", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = srv.Update(ctx, func(s *coordinator.State) error {
		r, err := ReadRegistry(s)
		if err != nil {
			return err
		}
		for _, invite := range r.Invites {
			invite.Expires = time.Now().Add(-time.Minute)
		}
		return WriteRegistry(s, r)
	}); err != nil {
		t.Fatal(err)
	}
	resumed, err := b.enroll(ctx, req, inv.Token)
	if err != nil || resumed.Self.ID != grant.Self.ID {
		t.Fatalf("lost response cannot be recovered after invitation expiry: %v", err)
	}
	n, signing := identity("another-worker")
	other := request(n, signing, "enroll")
	for _, token := range []string{unused.Token, inv.Token} {
		if _, err := b.enroll(ctx, other, token); err == nil {
			t.Fatal("expired capability admitted a different identity")
		}
	}
	forged := Sign(req, signing)
	if _, err := b.enroll(ctx, forged, inv.Token); err == nil {
		t.Fatal("consumed capability recovery accepted another signer")
	}
}
