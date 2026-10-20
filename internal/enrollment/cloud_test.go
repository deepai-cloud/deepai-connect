package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"tailscale.com/tailcfg"
)

func declaredCloud() *cloudconfig.Cloud {
	return &cloudconfig.Cloud{
		APIVersion: cloudconfig.APIVersion, Kind: cloudconfig.Kind, Name: "personal-cloud",
		Network:   cloudconfig.Network{Domain: "mesh.example.com", HostCIDR: "100.64.0.0/10", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16"},
		Bootstrap: cloudconfig.Bootstrap{Node: "hub-initial", Image: "connect:v1", Voters: 3},
		Nodes: map[string]cloudconfig.Node{
			"hub-initial": {Role: "hub", Voter: true, PublicIP: "203.0.113.10", RelayDomain: "relay.example.com", Connection: cloudconfig.Connection{SSH: "root@203.0.113.10"}},
			"my-worker":   {Role: "worker", Labels: map[string]string{"location": "home"}},
			"hub-second":  {Role: "hub", PublicIP: "203.0.113.20", RelayDomain: "relay-two.example.com", Connection: cloudconfig.Connection{SSH: "root@203.0.113.20"}},
		},
	}
}

func applyDeclaredCloud(t *testing.T, b *Broker, c *cloudconfig.Cloud, policy []tailcfg.FilterRule) string {
	t.Helper()
	var revision string
	if err := b.Update(context.Background(), func(s *coordinator.State) error {
		var err error
		revision, err = ApplyCloud(s, c, policy)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestCloudApplyIsStableAndPreservesIdentityAndPolicy(t *testing.T) {
	b, _, _ := fixture(t)
	c := declaredCloud()
	before, _ := b.Store.Load(context.Background())
	first := applyDeclaredCloud(t, b, c, nil)
	second := applyDeclaredCloud(t, b, c, nil)
	if first != second || len(first) != 64 {
		t.Fatal("repeated apply changed cloud revision")
	}
	after, _ := b.Store.Load(context.Background())
	if !reflect.DeepEqual(before.Nodes, after.Nodes) || !reflect.DeepEqual(before.Policy, after.Policy) {
		t.Fatal("apply changed existing membership or an unspecified policy")
	}
	r, err := ReadRegistry(after)
	if err != nil || r.Cloud == nil || r.Cloud.Revision != first || !reflect.DeepEqual(r.Cloud.Policy, before.Policy) {
		t.Fatal("effective desired cloud was not persisted")
	}
	// Labels change desired state without changing any identity.
	worker := c.Nodes["my-worker"]
	worker.Labels["location"] = "office"
	c.Nodes["my-worker"] = worker
	third := applyDeclaredCloud(t, b, c, nil)
	if third == first {
		t.Fatal("changed labels did not change cloud revision")
	}
	denyAll := []tailcfg.FilterRule{}
	fourth := applyDeclaredCloud(t, b, c, denyAll)
	final, _ := b.Store.Load(context.Background())
	if fourth == third || final.Policy == nil || len(final.Policy) != 0 || !reflect.DeepEqual(before.Nodes, final.Nodes) {
		t.Fatal("explicit empty policy was lost or changed membership")
	}
	if again := applyDeclaredCloud(t, b, c, nil); again != fourth {
		t.Fatal("unspecified policy lost effective deny-all configuration")
	}
}

func TestCloudRejectsDestructiveChangesAtomically(t *testing.T) {
	changes := map[string]func(*cloudconfig.Cloud){
		"host-network":    func(c *cloudconfig.Cloud) { c.Network.HostCIDR = "100.96.0.0/16" },
		"pod-network":     func(c *cloudconfig.Cloud) { c.Network.PodCIDR = "10.44.0.0/16" },
		"service-network": func(c *cloudconfig.Cloud) { c.Network.ServiceCIDR = "10.45.0.0/16" },
		"domain":          func(c *cloudconfig.Cloud) { c.Network.Domain = "other.example.com" },
		"image":           func(c *cloudconfig.Cloud) { c.Bootstrap.Image = "connect:v2" },
		"voters":          func(c *cloudconfig.Cloud) { c.Bootstrap.Voters = 5 },
		"name":            func(c *cloudconfig.Cloud) { c.Name = "another-cloud" },
		"remove-member":   func(c *cloudconfig.Cloud) { delete(c.Nodes, "hub-initial") },
		"change-role":     func(c *cloudconfig.Cloud) { c.Nodes["hub-initial"] = cloudconfig.Node{Role: "worker"} },
		"public-ip": func(c *cloudconfig.Cloud) {
			n := c.Nodes["hub-initial"]
			n.PublicIP = "203.0.113.11"
			c.Nodes["hub-initial"] = n
		},
		"relay-domain": func(c *cloudconfig.Cloud) {
			n := c.Nodes["hub-initial"]
			n.RelayDomain = "different.example.com"
			c.Nodes["hub-initial"] = n
		},
		"bootstrap": func(c *cloudconfig.Cloud) {
			c.Bootstrap.Node = "hub-second"
			n := c.Nodes["hub-second"]
			n.Voter = true
			c.Nodes["hub-second"] = n
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b, _, _ := fixture(t)
			applyDeclaredCloud(t, b, declaredCloud(), nil)
			s, _ := b.Store.Load(context.Background())
			before, _ := json.Marshal(s)
			c := declaredCloud()
			change(c)
			if _, err := ApplyCloud(s, c, []tailcfg.FilterRule{}); err == nil {
				t.Fatal("destructive cloud change accepted")
			}
			after, _ := json.Marshal(s)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected cloud partially mutated policy or enrollment")
			}
		})
	}
}

func TestCloudAdoptionChecksRegisteredHubEndpoints(t *testing.T) {
	b, _, _ := fixture(t)
	s, _ := b.Store.Load(context.Background())
	s.DERPMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{900: {Nodes: []*tailcfg.DERPNode{{Name: "hub-initial", HostName: "other.example.com", IPv4: "203.0.113.10"}}}}}
	if _, err := ApplyCloud(s, declaredCloud(), nil); err == nil {
		t.Fatal("adopted hub with different registered relay")
	}
	s.DERPMap = nil
	c := declaredCloud()
	hub := c.Nodes["hub-initial"]
	hub.PublicIP = "203.0.113.99"
	c.Nodes["hub-initial"] = hub
	if _, err := ApplyCloud(s, c, nil); err == nil {
		t.Fatal("adopted hub with different public IP")
	}
}

func TestNamedInvitationsAreBoundAndOldUnboundInvitationsClose(t *testing.T) {
	b, _, backend := fixture(t)
	ctx := context.Background()
	legacy, _ := b.Invite(ctx, "worker", false, time.Hour)
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	if _, err := b.Invite(ctx, "worker", false, time.Hour); err == nil {
		t.Fatal("declarative cloud issued unbound invitation")
	}
	for _, name := range []string{"undeclared", "hub-initial"} {
		if _, err := b.InviteNode(ctx, name, time.Hour); err == nil {
			t.Fatalf("invited unavailable node %q", name)
		}
	}
	inv, err := b.InviteNode(ctx, "my-worker", time.Hour)
	if err != nil || inv.Name != "my-worker" || inv.Role != "worker" {
		t.Fatal("could not issue named invitation", err)
	}
	n, k := identity("other-worker")
	if _, err := b.enroll(ctx, request(n, k, "enroll"), inv.Token); err == nil {
		t.Fatal("invitation claimed a different node name")
	}
	n.Hostname = "my-worker"
	n.Endpoints = nil // A NAT'd worker needs no public address or SSH access.
	if _, err := b.enroll(ctx, request(n, k, "enroll"), legacy.Token); err == nil {
		t.Fatal("old unbound invitation bypassed cloud declaration")
	}
	g, err := b.enroll(ctx, request(n, k, "enroll"), inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	if g.Configuration == nil || g.Configuration.Name != "my-worker" || g.Configuration.Node.Labels["location"] != "home" || backend.tokens.Load() != 0 {
		t.Fatal("enrollment did not return only its own configuration before credentials")
	}
	if err := ValidateGrant(inv, n, g, false); err != nil {
		t.Fatal(err)
	}
}

func TestNamedHubInvitationSuppliesAndEnforcesEndpoints(t *testing.T) {
	b, _, _ := fixture(t)
	ctx := context.Background()
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	inv, err := b.InviteNode(ctx, "hub-second", time.Hour)
	if err != nil || inv.PublicIP != "203.0.113.20" || inv.RelayDomain != "relay-two.example.com" {
		t.Fatal("missing hub endpoint metadata", err)
	}
	n, k := identity("hub-second")
	if _, err := b.enroll(ctx, request(n, k, "enroll"), inv.Token); err == nil {
		t.Fatal("hub joined with undeclared endpoint")
	}
	n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")}
	g, err := b.enroll(ctx, request(n, k, "enroll"), inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	if g.Configuration.Node.Connection.SSH != "" {
		t.Fatal("configuration disclosed administrative SSH connection")
	}
	if err := ValidateGrant(inv, n, g, false); err != nil {
		t.Fatal(err)
	}
}

func TestCloudDeclarationChangesInvalidateOnlyUnusedNodeCapabilities(t *testing.T) {
	b, _, _ := fixture(t)
	ctx := context.Background()
	c := declaredCloud()
	applyDeclaredCloud(t, b, c, nil)
	old, _ := b.InviteNode(ctx, "hub-second", time.Hour)
	hub := c.Nodes["hub-second"]
	hub.PublicIP = "203.0.113.21"
	c.Nodes["hub-second"] = hub
	applyDeclaredCloud(t, b, c, nil)
	n, k := identity("hub-second")
	n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.21:41641")}
	if _, err := b.enroll(ctx, request(n, k, "enroll"), old.Token); err == nil {
		t.Fatal("old capability accepted changed hub endpoint declaration")
	}
	current, _ := b.InviteNode(ctx, "hub-second", time.Hour)
	g, err := b.enroll(ctx, request(n, k, "enroll"), current.Token)
	if err != nil {
		t.Fatal(err)
	}
	// A consumed capability recovers only the original device and address.
	resumed, err := b.enroll(ctx, request(n, k, "enroll"), current.Token)
	if err != nil || resumed.Self.ID != g.Self.ID || !reflect.DeepEqual(resumed.Self.Addresses, g.Self.Addresses) {
		t.Fatal("named invitation replay changed durable identity", err)
	}
	forged, differentKey := identity("hub-second")
	if _, err := b.enroll(ctx, request(forged, differentKey, "enroll"), current.Token); err == nil {
		t.Fatal("named invitation replay replaced identity")
	}
	// Names remain reserved even when another invitation was issued beforehand.
	if _, err := b.InviteNode(ctx, "hub-second", time.Hour); err == nil {
		t.Fatal("enrolled name was offered for replacement")
	}
}

func TestCloudRejectsMalformedPolicyWithoutMutation(t *testing.T) {
	b, _, _ := fixture(t)
	s, _ := b.Store.Load(context.Background())
	before, _ := json.Marshal(s)
	if _, err := ApplyCloud(s, declaredCloud(), []tailcfg.FilterRule{{SrcIPs: []string{"not-an-address"}}}); err == nil {
		t.Fatal("malformed policy accepted")
	}
	after, _ := json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("malformed policy partially committed desired cloud")
	}
}

func TestAuthenticatedConfigPullWorksWithoutInvitationOrBackend(t *testing.T) {
	b, srv, backend := fixture(t)
	ctx := context.Background()
	c := declaredCloud()
	applyDeclaredCloud(t, b, c, nil)
	inv, _ := b.InviteNode(ctx, "my-worker", time.Hour)
	n, k := identity("my-worker")
	initial, err := b.enroll(ctx, request(n, k, "enroll"), inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	oldRevision := initial.Configuration.Revision
	if err := srv.Update(ctx, func(s *coordinator.State) error {
		r, err := ReadRegistry(s)
		if err != nil {
			return err
		}
		r.Invites[coordinator.TokenHash(inv.Token)].Expires = time.Now().Add(-time.Hour)
		return WriteRegistry(s, r)
	}); err != nil {
		t.Fatal(err)
	}
	c.Nodes["my-worker"].Labels["location"] = "office"
	newRevision := applyDeclaredCloud(t, b, c, nil)
	backend.healthy = func() error { return errors.New("Kubernetes API unavailable") }
	backend.probe = func() error { return errors.New("overlay probe unavailable") }
	send := func(req Request) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/config", bytes.NewReader(raw)))
		return w
	}
	w := send(request(n, k, "config"))
	var g Grant
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &g) != nil {
		t.Fatalf("config pull failed: HTTP %d %s", w.Code, w.Body.String())
	}
	if g.Token != "" || backend.tokens.Load() != 0 || g.Self.ID != initial.Self.ID || g.Configuration.Revision == oldRevision || g.Configuration.Revision != newRevision || g.Configuration.Node.Labels["location"] != "office" {
		t.Fatal("config pull changed identity, leaked credentials or returned stale desired state")
	}
	inv.Expires = time.Now().Add(-time.Hour)
	inv.Token = ""
	if err := ValidateGrant(inv, n, g, false); err != nil {
		t.Fatal("configuration validation depends on expired invitation bearer", err)
	}
	forged, wrong := identity("my-worker")
	for _, req := range []Request{request(n, wrong, "config"), request(forged, wrong, "config")} {
		if got := send(req).Code; got != 403 {
			t.Fatalf("forged configuration access returned HTTP %d", got)
		}
	}
	if err := srv.Update(ctx, func(s *coordinator.State) error { s.Nodes[n.MachineKey].Revoked = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := send(request(n, k, "config")).Code; got != 403 {
		t.Fatal("revoked member fetched configuration")
	}
}

func TestDeclaredConfigurationValidationRejectsIdentityAndMetadataChanges(t *testing.T) {
	b, _, _ := fixture(t)
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	inv, _ := b.InviteNode(context.Background(), "my-worker", time.Hour)
	n, k := identity("my-worker")
	g, err := b.enroll(context.Background(), request(n, k, "enroll"), inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*Grant){
		"missing":  func(g *Grant) { g.Configuration = nil },
		"name":     func(g *Grant) { g.Configuration.Name = "other" },
		"role":     func(g *Grant) { g.Configuration.Node.Role = "hub" },
		"voter":    func(g *Grant) { g.Configuration.Node.Voter = true },
		"revision": func(g *Grant) { g.Configuration.Revision = strings.Repeat("g", 64) },
		"ssh":      func(g *Grant) { g.Configuration.Node.Connection.SSH = "root@example.com" },
		"label": func(g *Grant) {
			g.Configuration.Node.Labels = map[string]string{"node-role.kubernetes.io/control-plane": "true"}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(g)
			var changed Grant
			_ = json.Unmarshal(raw, &changed)
			change(&changed)
			if err := ValidateGrant(inv, n, changed, false); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestNamedInvitationFileRejectsMalformedCapabilities(t *testing.T) {
	b, _, _ := fixture(t)
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	inv, _ := b.InviteNode(context.Background(), "hub-second", time.Hour)
	path := filepath.Join(t.TempDir(), "hub.invite")
	write := func(raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(inv)
	write(raw)
	if got, err := ReadInvitation(path); err != nil || got.Name != inv.Name || got.PublicIP != inv.PublicIP || got.RelayDomain != inv.RelayDomain {
		t.Fatal("valid named invitation could not be read", err)
	}
	changes := map[string]func(*Invitation){
		"name":             func(inv *Invitation) { inv.Name = "../other" },
		"token":            func(inv *Invitation) { inv.Token = "dai-" + strings.Repeat("z", 64) },
		"public-ip":        func(inv *Invitation) { inv.PublicIP = "127.0.0.1" },
		"relay":            func(inv *Invitation) { inv.RelayDomain = "https://relay.example.com" },
		"unbound-metadata": func(inv *Invitation) { inv.Name = "" },
		"worker-metadata":  func(inv *Invitation) { inv.Role = "worker" },
		"expired":          func(inv *Invitation) { inv.Expires = time.Now().Add(-time.Hour) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := inv
			change(&changed)
			encoded, _ := json.Marshal(changed)
			write(encoded)
			if _, err := ReadInvitation(path); err == nil {
				t.Fatal("malformed named invitation accepted")
			}
		})
	}
	for _, altered := range [][]byte{append(append([]byte{}, raw...), []byte(`{}`)...), []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"unknown":true`, 1))} {
		write(altered)
		if _, err := ReadInvitation(path); err == nil {
			t.Fatal("trailing data or unknown invitation fields accepted")
		}
	}
}
