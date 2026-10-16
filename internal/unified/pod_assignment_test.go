package unified

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

func TestUpdatePodRoutesWaitsForReadyNodesDelayedAllocation(t *testing.T) {
	// Keep the Unix agent socket below macOS's sockaddr_un path limit.
	dir, err := os.MkdirTemp("/tmp", "dai-pod-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	i := testInstallation(dir)
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	seed, _, err := seedState(id, i)
	if err != nil {
		t.Fatal(err)
	}
	if err = hostnet.SaveState(i.Config.AgentStateDir, seed); err != nil {
		t.Fatal(err)
	}
	updates := make(chan *hostnet.State, 1)
	listener, err := net.Listen("unix", hostnet.SocketPath(i.Config.AgentStateDir))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var state hostnet.State
		if r.Method != "POST" || r.URL.Path != "/state" || json.NewDecoder(r.Body).Decode(&state) != nil {
			w.WriteHeader(400)
			return
		}
		updates <- &state
		w.WriteHeader(204)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	calls := 0
	runner := workerRunner(func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if !strings.HasSuffix(strings.Join(args, " "), "get node hub-one -o json") {
			t.Fatalf("unexpected Kubernetes query: %v", args)
		}
		calls++
		if calls == 1 {
			// This is the real first-hub race: Ready does not imply assigned CIDR.
			return []byte(`{"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"}]}}`), nil
		}
		return []byte(`{"spec":{"podCIDR":"10.42.0.0/24","podCIDRs":["10.42.0.0/24"]}}`), nil
	})
	m, err := cluster.New(i.Config, runner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = updatePodRoutes(ctx, dir, i, m); err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")}
	if calls != 2 || !slices.Equal(i.PodRoutes, want) {
		t.Fatalf("allocation was not retried and recorded: calls=%d routes=%v", calls, i.PodRoutes)
	}
	saved, err := loadInstallation(dir)
	if err != nil || !slices.Equal(saved.PodRoutes, want) {
		t.Fatalf("assigned routes not persisted: %v", err)
	}
	select {
	case state := <-updates:
		if !slices.Equal(state.PodRoutes, want) || state.Self.Key != id.Node.Public() {
			t.Fatal("agent update lost trusted allocation or overlay identity")
		}
	default:
		t.Fatal("assigned routes were not applied to the existing host agent")
	}
}

func TestUpdatePodRoutesCancelsUnassignedAllocation(t *testing.T) {
	dir := t.TempDir()
	i := testInstallation(dir)
	calls := 0
	runner := workerRunner(func(context.Context, []byte, string, ...string) ([]byte, error) {
		calls++
		return []byte(`{"spec":{}}`), nil
	})
	m, err := cluster.New(i.Config, runner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err = updatePodRoutes(ctx, dir, i, m); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unassigned allocation did not honor cancellation: %v", err)
	}
	if calls != 1 || len(i.PodRoutes) != 0 {
		t.Fatal("canceled allocation was retried or published")
	}
}

func TestUpdatePodRoutesRejectsInvalidAllocationImmediately(t *testing.T) {
	for _, response := range []string{
		`{"spec":{"podCIDR":"invalid"}}`,
		`{"spec":{"podCIDR":"10.44.0.0/24"}}`,
		`{"spec":{"podCIDRs":[""]}}`,
		`{"spec":`,
	} {
		t.Run(response, func(t *testing.T) {
			dir := t.TempDir()
			i := testInstallation(dir)
			calls := 0
			runner := workerRunner(func(context.Context, []byte, string, ...string) ([]byte, error) {
				calls++
				return []byte(response), nil
			})
			m, err := cluster.New(i.Config, runner)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if err = updatePodRoutes(ctx, dir, i, m); err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("invalid allocation must fail without waiting: %v", err)
			}
			if calls != 1 || len(i.PodRoutes) != 0 {
				t.Fatal("invalid allocation was retried or published")
			}
		})
	}
}
