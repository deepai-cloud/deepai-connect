package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

type cloudApplyHub struct {
	store                           *coordinator.MemoryStore
	server                          *coordinator.Server
	prepared, updated, labeled      int
	prepareErr, updateErr, labelErr error
	beforeUpdate                    func()
}

func (h *cloudApplyHub) Load(ctx context.Context) (*coordinator.State, error) {
	return h.store.Load(ctx)
}
func (h *cloudApplyHub) Update(ctx context.Context, change func(*coordinator.State) error) error {
	h.updated++
	if h.beforeUpdate != nil {
		h.beforeUpdate()
	}
	if h.updateErr != nil {
		return h.updateErr
	}
	return h.server.Update(ctx, change)
}
func (h *cloudApplyHub) Prepare(context.Context, *installation) error {
	h.prepared++
	return h.prepareErr
}
func (h *cloudApplyHub) Labels(context.Context) error { h.labeled++; return h.labelErr }
func (h *cloudApplyHub) Close()                       {}

type cloudApplyFixture struct {
	dir    string
	bundle *cloudBundle
	local  *installation
	hub    *cloudApplyHub
	rt     cloudRuntime
}

func newCloudApplyFixture(t *testing.T, installed bool) *cloudApplyFixture {
	t.Helper()
	_, c := cloudFixture(t)
	dir := filepath.Join(t.TempDir(), "installation")
	i := testInstallation(dir)
	i.Phase, i.RelayDomain, i.Config.ConnectImage = "ready", c.Nodes["hub-one"].RelayDomain, c.Bootstrap.Image
	i.Services.Image = c.Bootstrap.Image
	i.Services.Hubs = []cluster.HubEndpoint{{Name: i.Config.Name, Hostname: i.RelayDomain, PublicIP: i.PublicIP}}
	store := &coordinator.MemoryStore{}
	srv, err := coordinator.New(context.Background(), coordinator.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	f := &cloudApplyFixture{dir: dir, bundle: &cloudBundle{Cloud: c}, local: i, hub: &cloudApplyHub{store: store, server: srv}}
	f.rt = cloudRuntime{
		requireHost: func() error { return nil },
		create:      func(context.Context, []string, *cloudBundle) error { t.Fatal("unexpected create"); return nil },
		resume: func(_ context.Context, dir string, i *installation) error {
			i.Phase = "ready"
			return saveInstallation(dir, i)
		},
		open: func(context.Context, *installation) (cloudHub, error) { return f.hub, nil },
		pull: func(context.Context, string) error { return nil },
	}
	if installed {
		f.seed(t)
	}
	return f
}

func (f *cloudApplyFixture) seed(t *testing.T) {
	t.Helper()
	id, err := hostnet.LoadOrCreateIdentity(f.local.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.Identity(f.dir); err != nil {
		t.Fatal(err)
	}
	_, node, err := seedState(id, f.local)
	if err != nil {
		t.Fatal(err)
	}
	err = f.hub.server.Update(context.Background(), func(s *coordinator.State) error {
		s.Network = f.local.Config.HostCIDR
		s.Policy = clusterPolicy(f.local.Config.HostCIDR, f.local.Config.PodCIDR, f.local.Config.ServiceCIDR)
		if err := coordinator.AllocateNode(s, node); err != nil {
			return err
		}
		c := f.bundle.Cloud
		r := enrollment.Registry{
			Cluster: enrollment.Cluster{ID: f.local.ClusterID, URL: f.local.Services.PublicURL, HostCIDR: c.Network.HostCIDR,
				PodCIDR: c.Network.PodCIDR, ServiceCIDR: c.Network.ServiceCIDR, DesiredVoters: c.Bootstrap.Voters, Image: c.Bootstrap.Image},
			Members: map[string]*enrollment.Member{node.MachineKey: {Name: node.Hostname, Role: "hub", Voter: true, Ready: true}},
			Invites: map[string]*enrollment.Invite{},
		}
		if err := enrollment.WriteRegistry(s, r); err != nil {
			return err
		}
		return storeServices(s, f.local.Services)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveInstallation(f.dir, f.local); err != nil {
		t.Fatal(err)
	}
}

func (f *cloudApplyFixture) apply(preview bool) error {
	return applyCloudWithRuntime(context.Background(), f.dir, f.bundle, preview, io.Discard, f.rt)
}

func cloudStateBytes(t *testing.T, store coordinator.Store) []byte {
	t.Helper()
	s, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cloudFileSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == ".lock" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files[relative] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCloudExistingHubPlanIsReadOnly(t *testing.T) {
	f := newCloudApplyFixture(t, true)
	state, files := cloudStateBytes(t, f.hub.store), cloudFileSnapshot(t, f.dir)
	f.rt.requireHost = func() error { t.Fatal("plan requested host privileges"); return nil }
	f.rt.pull = func(context.Context, string) error { t.Fatal("plan pulled configuration"); return nil }
	if err := f.apply(true); err != nil {
		t.Fatal(err)
	}
	if f.hub.prepared != 0 || f.hub.updated != 0 || f.hub.labeled != 0 ||
		!bytes.Equal(state, cloudStateBytes(t, f.hub.store)) || !reflect.DeepEqual(files, cloudFileSnapshot(t, f.dir)) {
		t.Fatal("plan modified the cluster or private installation")
	}
}

func TestCloudAdoptionFailureRetriesWithSameIdentity(t *testing.T) {
	for _, failure := range []string{"services", "transaction", "pull", "labels"} {
		t.Run(failure, func(t *testing.T) {
			f := newCloudApplyFixture(t, true)
			files := cloudFileSnapshot(t, f.dir)
			original := cloudStateBytes(t, f.hub.store)
			fail := errors.New("injected " + failure + " failure")
			switch failure {
			case "services":
				f.hub.prepareErr = fail
			case "transaction":
				f.hub.updateErr = fail
			case "pull":
				f.rt.pull = func(context.Context, string) error { return fail }
			case "labels":
				f.hub.labelErr = fail
			}
			if err := f.apply(false); !errors.Is(err, fail) {
				t.Fatalf("failure was hidden: %v", err)
			}
			i, err := loadInstallation(f.dir)
			if err != nil {
				t.Fatal(err)
			}
			s, err := f.hub.store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			r, err := enrollment.ReadRegistry(s)
			if err != nil {
				t.Fatal(err)
			}
			committed := failure == "pull" || failure == "labels"
			if (r.Cloud != nil) != committed || (i.BootstrapCloud != nil) != committed {
				t.Fatal("failure left an incorrect adoption/retry marker")
			}
			if !committed && !bytes.Equal(original, cloudStateBytes(t, f.hub.store)) {
				t.Fatal("failed preparation/transaction changed the registry")
			}
			f.hub.prepareErr, f.hub.updateErr, f.hub.labelErr = nil, nil, nil
			f.rt.pull = func(context.Context, string) error { return nil }
			if err := f.apply(false); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
			s, _ = f.hub.store.Load(context.Background())
			after, err := enrollment.ReadRegistry(s)
			if err != nil || after.Cloud == nil {
				t.Fatalf("retry did not commit cloud: %v", err)
			}
			if committed && r.Cloud.Revision != after.Cloud.Revision {
				t.Fatal("unchanged retry manufactured a new desired revision")
			}
			current := cloudFileSnapshot(t, f.dir)
			for path, prior := range files {
				if path != "unified.json" && current[path] != prior {
					t.Fatalf("retry changed original private state %s", path)
				}
			}
			signer, err := enrollment.LoadIdentity(f.dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range after.Members {
				if !bytes.Equal(m.PublicKey, signer.Public().(ed25519.PublicKey)) {
					t.Fatal("retry did not preserve/bind original signer")
				}
			}
		})
	}
}

func TestCloudApplyPreservesInterveningLocalEgressConfiguration(t *testing.T) {
	f := newCloudApplyFixture(t, true)
	f.rt.open = func(context.Context, *installation) (cloudHub, error) {
		current, err := loadInstallation(f.dir)
		if err != nil {
			t.Fatal(err)
		}
		current.GatewayInterface = "eth0"
		current.PodRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}
		if err := saveInstallation(f.dir, current); err != nil {
			t.Fatal(err)
		}
		return f.hub, nil
	}
	if err := f.apply(false); err != nil {
		t.Fatal(err)
	}
	current, err := loadInstallation(f.dir)
	if err != nil || current.GatewayInterface != "eth0" || !reflect.DeepEqual(current.PodRoutes, []netip.Prefix{netip.MustParsePrefix("10.42.2.0/24")}) {
		t.Fatalf("apply overwrote an intervening local configuration: %v", err)
	}
}

func TestCloudApplyRechecksMembershipAtCommit(t *testing.T) {
	f := newCloudApplyFixture(t, true)
	f.hub.beforeUpdate = func() {
		if err := f.hub.server.Update(context.Background(), func(s *coordinator.State) error {
			r, err := enrollment.ReadRegistry(s)
			if err != nil {
				return err
			}
			for _, m := range r.Members {
				m.PublicKey = bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
			}
			return enrollment.WriteRegistry(s, r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.apply(false); err == nil {
		t.Fatal("apply authorized membership that changed after preview")
	}
	s, _ := f.hub.store.Load(context.Background())
	r, err := enrollment.ReadRegistry(s)
	if err != nil || r.Cloud != nil {
		t.Fatalf("rejected transaction partially committed a cloud: %v", err)
	}
	i, err := loadInstallation(f.dir)
	if err != nil || i.BootstrapCloud != nil || f.hub.labeled != 0 {
		t.Fatal("rejected transaction persisted an adoption marker or reconciled labels")
	}
}

func TestCloudMissingSignerFailsBeforePreparingServices(t *testing.T) {
	f := newCloudApplyFixture(t, true)
	if err := os.Remove(filepath.Join(f.dir, "enrollment.key")); err != nil {
		t.Fatal(err)
	}
	before := cloudStateBytes(t, f.hub.store)
	if err := f.apply(false); err == nil {
		t.Fatal("missing original signer was replaced")
	}
	if f.hub.prepared != 0 || !bytes.Equal(before, cloudStateBytes(t, f.hub.store)) {
		t.Fatal("missing identity triggered service/registry mutation")
	}
	if _, err := enrollment.LoadIdentity(f.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("apply generated a replacement signer")
	}
}

func TestCloudInterruptedBootstrapResumesAndCleansTemporaryTLS(t *testing.T) {
	f := newCloudApplyFixture(t, false)
	f.bundle.Certificate, f.bundle.Key = []byte("test-cert"), []byte("test-key")
	f.bundle.Cloud.Bootstrap.TLSCertFile, f.bundle.Cloud.Bootstrap.TLSKeyFile = "private/cert", "private/key"
	var tlsPaths []string
	creates, resumes := 0, 0
	f.rt.create = func(_ context.Context, args []string, b *cloudBundle) error {
		creates++
		for j, arg := range args {
			if arg == "--tls-cert" || arg == "--tls-key" {
				path := args[j+1]
				data, err := os.ReadFile(path)
				expected := map[string]string{"--tls-cert": "test-cert", "--tls-key": "test-key"}[arg]
				if err != nil || string(data) != expected {
					t.Fatal("bootstrap did not receive temporary TLS material")
				}
				tlsPaths = append(tlsPaths, path)
			}
		}
		if len(tlsPaths) != 2 {
			t.Fatal("bootstrap omitted a TLS file")
		}
		if b.Cloud.Name != f.bundle.Cloud.Name {
			t.Fatal("bootstrap lost declarative inputs")
		}
		f.local.Phase, f.local.BootstrapCloud = "network", b.Cloud
		f.seed(t)
		return errors.New("installation saved; simulated power loss")
	}
	if err := f.apply(false); err == nil || !strings.Contains(err.Error(), "power loss") {
		t.Fatalf("bootstrap failure not reported: %v", err)
	}
	for _, path := range tlsPaths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("temporary TLS material survived failed bootstrap")
		}
	}
	before := cloudFileSnapshot(t, f.dir)
	f.rt.resume = func(_ context.Context, dir string, i *installation) error {
		resumes++
		i.Phase = "ready"
		return saveInstallation(dir, i)
	}
	if err := f.apply(false); err != nil {
		t.Fatalf("interrupted bootstrap did not resume: %v", err)
	}
	if creates != 1 || resumes != 1 {
		t.Fatalf("retry recreated an installation: creates=%d resumes=%d", creates, resumes)
	}
	after := cloudFileSnapshot(t, f.dir)
	for path, data := range before {
		if path != "unified.json" && after[path] != data {
			t.Fatalf("resume replaced private state %s", path)
		}
	}
}

func TestCloudRejectsDestructiveChangesBeforeHostOperations(t *testing.T) {
	for _, change := range []func(*cloudconfig.Cloud){
		func(c *cloudconfig.Cloud) { c.Network.PodCIDR = "10.52.0.0/16" },
		func(c *cloudconfig.Cloud) { c.Bootstrap.Image = "registry.example.com/connect:v2" },
		func(c *cloudconfig.Cloud) { c.Network.Domain = "different.example.com" },
		func(c *cloudconfig.Cloud) { c.Bootstrap.Voters = 5 },
	} {
		f := newCloudApplyFixture(t, true)
		change(f.bundle.Cloud)
		if err := f.apply(false); err == nil {
			t.Fatal("apply accepted an implicit migration")
		}
		if f.hub.prepared != 0 || f.hub.updated != 0 {
			t.Fatal("rejected migration performed host operations")
		}
	}
}
