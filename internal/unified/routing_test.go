package unified

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"tailscale.com/tailcfg"
)

func TestManagedWorkerAdvertisesAssignedPodsAndDiscoveredRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store := &coordinator.MemoryStore{}
	control, err := coordinator.New(ctx, coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	server := httptest.NewServer(control.Handler())
	defer server.Close()
	installation := testInstallation(t.TempDir())
	worker, err := hostnet.LoadOrCreateIdentity(installation.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, node, err := seedState(worker, installation)
	if err != nil {
		t.Fatal(err)
	}
	pod := netip.MustParsePrefix("10.42.7.0/24")
	node.Role = "worker"
	node.ApprovedRoutes = []netip.Prefix{pod}
	node.Hostinfo = &tailcfg.Hostinfo{Hostname: node.Hostname, NetInfo: &tailcfg.NetInfo{PreferredDERP: 901}}
	state.Self = node.TailNode()
	state.PodRoutes = []netip.Prefix{pod}
	state.CoordinatorURL = server.URL
	observer, err := hostnet.LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other := nodeFor(observer, "observer", "client", nil)
	if err = control.Update(ctx, func(s *coordinator.State) error {
		s.Policy = state.PacketFilter
		if err := coordinator.AllocateNode(s, node); err != nil {
			return err
		}
		return coordinator.AllocateNode(s, &other)
	}); err != nil {
		t.Fatal(err)
	}
	response, err := fetchMap(ctx, worker, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Node.HomeDERP != 901 {
		t.Fatalf("discovered relay lost: %d", response.Node.HomeDERP)
	}
	if !slices.Contains(response.Node.AllowedIPs, pod) {
		t.Fatal("assigned worker pod prefix was not authorized")
	}
	client := coordinator.Client{ServerURL: server.URL, MachineKey: observer.Machine}
	response, err = client.Map(ctx, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: observer.Node.Public(), DiscoKey: observer.Disco.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Peers) != 1 || !slices.Contains(response.Peers[0].AllowedIPs, pod) || response.Peers[0].HomeDERP != 901 {
		t.Fatal("private peer cannot authenticate pod-sourced traffic or find the worker relay")
	}
}

func TestPodRouteParserRejectsMissingAndNonCanonicalAssignments(t *testing.T) {
	for _, value := range []string{"", "10.42.0.1/24", "::/64", "invalid"} {
		if _, err := parsePodRoutes(value, nil); err == nil {
			t.Fatalf("accepted invalid assignment %q", value)
		}
	}
	got, err := parsePodRoutes("10.42.7.0/24", nil)
	if err != nil || len(got) != 1 || got[0] != netip.MustParsePrefix("10.42.7.0/24") {
		t.Fatal(got, err)
	}
}
