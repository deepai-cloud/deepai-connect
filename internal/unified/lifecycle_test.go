package unified

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
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

func testInstallation(dir string) *installation {
	return &installation{Version: 1, Phase: "network", ClusterID: "test-cluster", Config: cluster.Config{Name: "hub-one", Role: "hub", OverlayIP: "100.64.0.1", HostCIDR: "100.64.0.0/10", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", DesiredVoters: 3, FirstHub: true, Voter: true, AgentStateDir: filepath.Join(dir, "network"), DataDir: filepath.Join(dir, "cluster")}, Services: cluster.ServiceConfig{PublicURL: "https://connect.example.com"}, PublicIP: "203.0.113.10"}
}

func TestOfflineSeedCoordinatorAdoptionPreservesIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dir := t.TempDir()
	installation := testInstallation(dir)
	id, err := hostnet.LoadOrCreateIdentity(installation.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	seed, node, err := seedState(id, installation)
	if err != nil {
		t.Fatal(err)
	}
	if err = hostnet.SaveState(installation.Config.AgentStateDir, seed); err != nil {
		t.Fatal(err)
	}
	restored, err := hostnet.LoadState(installation.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := hostnet.LoadOrCreateIdentity(installation.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.Validate(reloaded, time.Now()); err != nil {
		t.Fatal(err)
	}
	store := &coordinator.MemoryStore{}
	control, err := coordinator.New(ctx, coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err = control.Update(ctx, func(st *coordinator.State) error {
		st.Policy = seed.PacketFilter
		copy := *node
		return coordinator.AllocateNode(st, &copy)
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := netip.MustParseAddrPort("198.51.100.15:41641")
	lan := netip.MustParseAddrPort("192.168.64.3:41641")
	recursive := netip.MustParseAddrPort("10.42.0.1:41641")
	server := httptest.NewServer(control.Handler())
	defer server.Close()
	// Local HTTP is only the test transport; production recovery retains the
	// authenticated public origin and starts with the persisted snapshot.
	for attempt := 0; attempt < 3; attempt++ {
		requestState := restored.Clone()
		requestState.CoordinatorURL = server.URL
		requestState.DirectHubEndpoints[requestState.Self.Key] = append(requestState.DirectHubEndpoints[requestState.Self.Key], recursive)
		response, err := fetchMap(ctx, reloaded, requestState, []netip.AddrPort{endpoint, lan, recursive, netip.MustParseAddrPort("[::ffff:10.43.0.10]:41641")}, false)
		if err != nil {
			t.Fatal(err)
		}
		if response.Node.Key != seed.Self.Key || response.Node.Machine != seed.Self.Machine || response.Node.DiscoKey != seed.Self.DiscoKey || response.Node.Addresses[0] != seed.Self.Addresses[0] {
			t.Fatal("coordinator adoption rotated bootstrap identity")
		}
		if !slices.Contains(response.Node.Endpoints, node.Endpoints[0]) || !slices.Contains(response.Node.Endpoints, endpoint) || !slices.Contains(response.Node.Endpoints, lan) {
			t.Fatal("bootstrap direct endpoint was lost during endpoint refresh")
		}
		if len(response.Node.Endpoints) != 3 {
			t.Fatalf("coordinator received recursive cluster endpoint candidates: %v", response.Node.Endpoints)
		}
		if response.Node.Name != seed.Self.Name {
			t.Fatalf("hostname drift on refresh %d: %s != %s", attempt, response.Node.Name, seed.Self.Name)
		}
		restored, err = restored.WithMap(response, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err = restored.Validate(reloaded, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

type lifecycleBackend struct {
	probeReady bool
	tokens     int
	nodeReady  bool
}

func (b *lifecycleBackend) PodRoutes(context.Context, string) ([]netip.Prefix, error) {
	return []netip.Prefix{netip.MustParsePrefix("10.42.1.0/24")}, nil
}

func (b *lifecycleBackend) Healthy(context.Context, []string) error { return nil }
func (b *lifecycleBackend) Token(context.Context, bool) (string, error) {
	b.tokens++
	return "K10" + strings.Repeat("a", 64) + "::server:test-token", nil
}
func (b *lifecycleBackend) ValidateNode(_ context.Context, _ coordinator.Node, _ bool, complete bool) error {
	if complete && !b.nodeReady {
		return errors.New("node not ready")
	}
	return nil
}
func (b *lifecycleBackend) Probe(context.Context, netip.Addr, ed25519.PublicKey) error {
	if !b.probeReady {
		return errors.New("overlay not reachable")
	}
	return nil
}

func TestEnrollmentOverlayBeforeKubernetesAndResume(t *testing.T) {
	ctx := context.Background()
	installation := testInstallation(t.TempDir())
	hubID, err := hostnet.LoadOrCreateIdentity(installation.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	seed, hub, err := seedState(hubID, installation)
	if err != nil {
		t.Fatal(err)
	}
	store := &coordinator.MemoryStore{}
	control, err := coordinator.New(ctx, coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err = control.Update(ctx, func(st *coordinator.State) error {
		st.Policy = seed.PacketFilter
		copy := *hub
		if err := coordinator.AllocateNode(st, &copy); err != nil {
			return err
		}
		return enrollment.WriteRegistry(st, enrollment.Registry{Cluster: enrollment.Cluster{ID: installation.ClusterID, URL: installation.Services.PublicURL, HostCIDR: installation.Config.HostCIDR, PodCIDR: installation.Config.PodCIDR, ServiceCIDR: installation.Config.ServiceCIDR, DesiredVoters: 3}, Invites: map[string]*enrollment.Invite{}, Members: map[string]*enrollment.Member{hub.MachineKey: {Name: hub.Hostname, Role: "hub", Voter: true, Ready: true}}})
	}); err != nil {
		t.Fatal(err)
	}
	backend := &lifecycleBackend{}
	broker := &enrollment.Broker{Store: store, Update: control.Update, Backend: backend}
	invite, err := broker.Invite(ctx, "worker", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	workerDir := t.TempDir()
	workerID, err := hostnet.LoadOrCreateIdentity(workerDir)
	if err != nil {
		t.Fatal(err)
	}
	node := nodeFor(workerID, "worker-one", "worker", []netip.AddrPort{netip.MustParseAddrPort("198.51.100.42:41641")})
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := func(action string) (int, enrollment.Grant) {
		t.Helper()
		signed := enrollment.Sign(enrollment.Request{ClusterID: invite.ClusterID, Action: action, Node: node, Issued: time.Now().UTC()}, signing)
		b, _ := json.Marshal(signed)
		req := httptest.NewRequest("POST", "/v1/"+action, bytes.NewReader(b))
		if action == "enroll" {
			req.Header.Set("Authorization", "Bearer "+invite.Token)
		}
		response := httptest.NewRecorder()
		broker.Handler().ServeHTTP(response, req)
		var grant enrollment.Grant
		if response.Code == http.StatusOK {
			if err := json.Unmarshal(response.Body.Bytes(), &grant); err != nil {
				t.Fatal(err)
			}
		}
		return response.Code, grant
	}
	status, grant := request("enroll")
	if status != http.StatusOK || grant.Token != "" || backend.tokens != 0 {
		t.Fatalf("network enrollment released K3s credential: %d %#v", status, grant)
	}
	if err = enrollment.ValidateGrant(invite, node, grant, false); err != nil {
		t.Fatal(err)
	}
	workerState := stateFromGrant(grant)
	if err = workerState.Validate(workerID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(workerState.Peers) != 1 || workerState.Peers[0].Key != hubID.Node.Public() || len(workerState.DirectHubEndpoints[hubID.Node.Public()]) == 0 {
		t.Fatal("join lacks directly reachable hub snapshot")
	}
	// Retrying a consumed enrollment with the same signed identity resumes the
	// same allocation instead of adding another node or losing its reservation.
	status, retry := request("enroll")
	if status != http.StatusOK || retry.Self.ID != grant.Self.ID || retry.Self.Addresses[0] != grant.Self.Addresses[0] {
		t.Fatal("enrollment retry was not idempotent")
	}
	status, _ = request("confirm")
	if status == http.StatusOK || backend.tokens != 0 {
		t.Fatal("K3s credential released before reverse overlay connectivity")
	}
	backend.probeReady = true
	status, confirmed := request("confirm")
	if status != http.StatusOK || backend.tokens != 1 {
		t.Fatal("verified overlay could not obtain K3s enrollment")
	}
	if err = enrollment.ValidateGrant(invite, node, confirmed, true); err != nil {
		t.Fatal(err)
	}
	status, _ = request("complete")
	if status == http.StatusOK {
		t.Fatal("enrollment completed before Kubernetes NodeReady")
	}
	backend.nodeReady = true
	status, _ = request("complete")
	if status != http.StatusOK {
		t.Fatal("ready node failed completion")
	}
	state, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := enrollment.ReadRegistry(state)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Members[node.MachineKey].Ready || len(state.Nodes) != 2 {
		t.Fatal("completed join was not durably recorded")
	}
}
