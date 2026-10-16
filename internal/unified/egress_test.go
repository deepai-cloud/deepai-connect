package unified

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

func TestInterruptedEgressDisableReplaysAfterDurableNormalization(t *testing.T) {
	dir := t.TempDir()
	i := testInstallation(dir)
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := seedState(id, i)
	if err != nil {
		t.Fatal(err)
	}
	s.EgressSources = slices.Clone(s.Self.Addresses)
	s.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if err = hostnet.SaveState(i.Config.AgentStateDir, s); err != nil {
		t.Fatal(err)
	}
	i.PendingEgressCleanup = &egressCleanup{Sources: slices.Clone(s.EgressSources), Interface: s.Interface, Address: s.Self.Addresses[0].Addr()}
	if err = saveInstallation(dir, i); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(i.Config.AgentStateDir, "identity.json")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	actions := egressCleanupActions{removeSources: func(_ context.Context, iface string, address netip.Addr, sources, protected []netip.Prefix) error {
		attempts++
		saved, e := loadInstallation(dir)
		if e != nil {
			t.Fatal(e)
		}
		cache, e := hostnet.LoadState(i.Config.AgentStateDir)
		if e != nil {
			t.Fatal(e)
		}
		if saved.PendingEgressCleanup == nil || len(saved.EgressSources) != 0 || len(cache.EgressSources) != 0 || len(cache.ApprovedRoutes) != 0 {
			t.Fatal("kernel policy removed before durable disabled state")
		}
		if !cache.ExpiresAt.Equal(s.ExpiresAt) || !cache.UpdatedAt.Equal(s.UpdatedAt) {
			t.Fatal("local disable renewed trusted cache")
		}
		if iface != s.Interface || address != s.Self.Addresses[0].Addr() || !slices.Equal(sources, s.EgressSources) || len(protected) != 3 {
			t.Fatal("cleanup broadened the old source scope")
		}
		if attempts == 1 {
			return errors.New("simulated kernel failure")
		}
		return nil
	}}
	if err = finishEgressCleanupWith(context.Background(), dir, i, actions); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	i, err = loadInstallation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if i.PendingEgressCleanup == nil {
		t.Fatal("failure discarded cleanup intent")
	}
	if err = finishEgressCleanupWith(context.Background(), dir, i, actions); err != nil {
		t.Fatal(err)
	}
	i, err = loadInstallation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if i.PendingEgressCleanup != nil {
		t.Fatal("successful cleanup did not commit")
	}
	if err = finishEgressCleanupWith(context.Background(), dir, i, actions); err != nil || attempts != 2 {
		t.Fatal("committed cleanup replayed")
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("disable changed device credentials")
	}
}

func TestEgressDisableRejectsConflictingOptionsBeforeHostAccess(t *testing.T) {
	for _, args := range [][]string{{"gateway", "--disable", "--interface", "eth0"}, {"egress", "--disable", "--source", "10.42.1.0/24"}} {
		if err := configureEgress(context.Background(), args[0], args[1:]); err == nil || err.Error() != "--disable cannot be combined with --interface or --source" {
			t.Fatalf("conflicting disable accepted: %v", err)
		}
	}
}
