package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

const exampleCloud = `apiVersion: connect.deepai.cloud/v1alpha1
kind: Cloud
name: home
bootstrap:
  node: hub-one
  image: registry.example.com/connect:v1
network:
  domain: connect.example.com
nodes:
  hub-one:
    role: hub
    publicIP: 203.0.113.10
    relayDomain: relay.example.com
    connection:
      ssh: root@203.0.113.10
  worker-one:
    role: worker
    labels:
      location: home
`

func cloudFixture(t *testing.T) (string, *cloudconfig.Cloud) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloud.yaml")
	if err := os.WriteFile(path, []byte(exampleCloud), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := cloudconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, c
}

func readCloudTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCloudSSHQuotingAndCredentialTransport(t *testing.T) {
	values := []string{"printf", "%s\\000", "quote'path", "$(touch /tmp/should-never-run)", "`id`"}
	args, err := cloudSSHArgs("root@hub.example.com", values...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), "StrictHostKeyChecking=no") {
		t.Fatal("SSH disables trust checking")
	}
	if _, err := exec.LookPath("sh"); err == nil {
		got, err := exec.Command("sh", "-c", args[len(args)-1]).Output()
		if err != nil || string(got) != strings.Join(values[2:], "\x00")+"\x00" {
			t.Fatalf("shell changed argument bytes: %q %v", got, err)
		}
	}
	for _, invalid := range []string{"-oProxyCommand=bad", "root@host;id", "root@host\nid"} {
		if _, err := cloudSSHArgs(invalid, "true"); err == nil {
			t.Fatalf("accepted SSH injection %q", invalid)
		}
	}
	path, _ := cloudFixture(t)
	body := strings.Replace(exampleCloud, "  image:", "  tlsCertFile: tls.crt\n  tlsKeyFile: tls.key\n  image:", 1)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"tls.crt": "test-cert", "tls.key": "test-private-key"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := cloudProcess
	defer func() { cloudProcess = original }()
	called := 0
	cloudProcess = func(_ context.Context, args []string, in io.Reader, _, _ io.Writer) error {
		called++
		if strings.Contains(strings.Join(args, " "), "test-private-key") {
			t.Fatal("private key exposed in process arguments")
		}
		var b cloudBundle
		if err := json.NewDecoder(in).Decode(&b); err != nil {
			t.Fatal(err)
		}
		if string(b.Key) != "test-private-key" || b.Cloud.Nodes["worker-one"].Connection.SSH != "" {
			t.Fatal("bundle lost bootstrap material or requires worker SSH")
		}
		return nil
	}
	if err := cloudCommand(context.Background(), "apply", []string{"-f", path}); err != nil || called != 1 {
		t.Fatalf("remote apply failed: %v %d", err, called)
	}
}

func TestCloudPlanDoesNotCreateStateOrReadTLSKeys(t *testing.T) {
	path, c := cloudFixture(t)
	dir := filepath.Join(t.TempDir(), "absent")
	var out bytes.Buffer
	if err := applyCloudLocal(context.Background(), dir, &cloudBundle{Cloud: c}, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "awaiting enrollment") {
		t.Fatalf("plan omitted pending nodes: %s", out.String())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("plan created installation state")
	}
	raw := strings.Replace(exampleCloud, "  image:", "  tlsCertFile: absent.crt\n  tlsKeyFile: absent.key\n  image:", 1)
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCloudBundle(path, false); err != nil {
		t.Fatalf("plan tried to read TLS keys: %v", err)
	}
}

func TestCloudBundlePreservesExplicitDenyPolicy(t *testing.T) {
	path, _ := cloudFixture(t)
	raw := strings.Replace(exampleCloud, "  domain:", "  packetPolicyFile: policy.json\n  domain:", 1)
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "policy.json"), []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := loadCloudBundle(path, false)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var remote cloudBundle
	if err := json.Unmarshal(wire, &remote); err != nil || remote.Policy == nil || len(remote.Policy) != 0 {
		t.Fatal("SSH transport changed explicit deny into unspecified policy")
	}
	if err := validateCloudBundle(&remote); err != nil {
		t.Fatal(err)
	}
}

func TestNamedJoinCannotOverrideDeclaredIdentity(t *testing.T) {
	inv := enrollment.Invitation{Name: "hub-two", Role: "hub", PublicIP: "203.0.113.20", RelayDomain: "relay2.example.com"}
	var name, ip, relay string
	if err := namedJoinOptions(&inv, &name, &ip, &relay); err != nil || name != inv.Name || ip != inv.PublicIP || relay != inv.RelayDomain {
		t.Fatalf("invitation settings not used: %v", err)
	}
	name = "different-node"
	if err := namedJoinOptions(&inv, &name, &ip, &relay); err == nil {
		t.Fatal("accepted another node name")
	}
}

func TestCloudInvitationIsSavedPrivatelyAndNeverOverwritten(t *testing.T) {
	path, _ := cloudFixture(t)
	dest := filepath.Join(t.TempDir(), "worker.invite")
	original := cloudProcess
	defer func() { cloudProcess = original }()
	calls := 0
	cloudProcess = func(_ context.Context, args []string, in io.Reader, out, _ io.Writer) error {
		calls++
		if in != nil || !strings.Contains(args[len(args)-1], "'--node' 'worker-one'") {
			t.Fatal("unexpected invitation transport")
		}
		return json.NewEncoder(out).Encode(enrollment.Invitation{Version: 1, Name: "worker-one", Role: "worker", ClusterID: "cluster", URL: "https://connect.example.com", Expires: time.Now().Add(time.Hour), Token: "dai-" + strings.Repeat("a", 64)})
	}
	if err := enrollCloudRemote(context.Background(), path, "worker-one", dest, defaultDir, time.Hour); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dest)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("invitation permissions: %v %v", info, err)
	}
	if err := enrollCloudRemote(context.Background(), path, "worker-one", dest, defaultDir, time.Hour); err == nil || calls != 1 {
		t.Fatal("existing private invitation was overwritten or new invitation issued")
	}
}

func TestAuthenticatedConfigurationPullPreservesInstallationAndOfflineCache(t *testing.T) {
	dir := t.TempDir()
	i := testInstallation(dir)
	i.Config.FirstHub, i.Config.Role, i.Config.Voter = false, "worker", false
	i.Config.Name, i.Config.ConnectImage = "worker-one", "registry.example.com/connect:v1"
	i.Config.OverlayIP, i.PublicIP = "100.64.0.2", ""
	i.Invitation = &enrollment.Invitation{ClusterID: i.ClusterID, URL: i.Services.PublicURL, Role: "worker", Name: "worker-one", Expires: time.Now().Add(-time.Hour)}
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = enrollment.Identity(dir); err != nil {
		t.Fatal(err)
	}
	if err = saveInstallation(dir, i); err != nil {
		t.Fatal(err)
	}
	before := readCloudTestFile(t, filepath.Join(dir, "unified.json"))
	node := nodeFor(id, i.Config.Name, i.Config.Role, nil)
	node.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
	g := enrollment.Grant{
		Cluster: enrollment.Cluster{ID: i.ClusterID, URL: i.Services.PublicURL, HostCIDR: i.Config.HostCIDR, PodCIDR: i.Config.PodCIDR, ServiceCIDR: i.Config.ServiceCIDR, DesiredVoters: 3, Image: i.Config.ConnectImage},
		Role:    "worker", Self: node.TailNode(), ServerURLs: []string{"https://100.64.0.1:6443"},
		Configuration: &enrollment.NodeConfiguration{Revision: strings.Repeat("a", 64), Name: i.Config.Name, Node: cloudconfig.Node{Role: "worker", Labels: map[string]string{"location": "home"}}},
	}
	exchange := func(_ context.Context, inv enrollment.Invitation, _ ed25519.PrivateKey, n coordinator.Node, action string) (enrollment.Grant, error) {
		if action != "config" || n.MachineKey != node.MachineKey || !inv.Expires.Before(time.Now()) {
			t.Fatal("pull did not reuse authenticated expired-invitation membership")
		}
		return g, nil
	}
	if err = pullConfiguration(context.Background(), dir, exchange); err != nil {
		t.Fatal(err)
	}
	cached := readCloudTestFile(t, filepath.Join(dir, "configuration.json"))
	after := readCloudTestFile(t, filepath.Join(dir, "unified.json"))
	if !bytes.Equal(before, after) || bytes.Contains(cached, []byte(`"token"`)) || len(cached) == 0 {
		t.Fatal("pull changed installation identity or cached credentials")
	}
	g.Cluster.PodCIDR = "10.52.0.0/16"
	if err = pullConfiguration(context.Background(), dir, exchange); err == nil {
		t.Fatal("accepted an implicit network migration")
	}
	offline := func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error) {
		return enrollment.Grant{}, errors.New("offline")
	}
	if err = pullConfiguration(context.Background(), dir, offline); err == nil {
		t.Fatal("offline pull claimed success")
	}
	unchanged := readCloudTestFile(t, filepath.Join(dir, "configuration.json"))
	if !bytes.Equal(cached, unchanged) {
		t.Fatal("failed pull destroyed saved configuration")
	}
}

func TestCloudAdoptionBindsOriginalHubSignerAndPreservesIdentity(t *testing.T) {
	i, srv, store, machine := firstHubResumeFixture(t)
	dir := filepath.Dir(i.Config.AgentStateDir)
	signer, err := enrollment.Identity(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(context.Background())
	if err := srv.Update(context.Background(), func(s *coordinator.State) error {
		return registerCloudHubSigner(dir, i, s)
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := store.Load(context.Background())
	r, _ := enrollment.ReadRegistry(after)
	if !bytes.Equal(r.Members[machine].PublicKey, signer.Public().(ed25519.PublicKey)) {
		t.Fatal("adoption did not bind the original signer")
	}
	oldNode, _ := json.Marshal(before.Nodes[machine])
	newNode, _ := json.Marshal(after.Nodes[machine])
	if !bytes.Equal(oldNode, newNode) {
		t.Fatal("adoption changed node allocation or identity")
	}
	r.Members[machine].PublicKey = bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	if err := enrollment.WriteRegistry(after, r); err != nil {
		t.Fatal(err)
	}
	if err := registerCloudHubSigner(dir, i, after); err == nil {
		t.Fatal("adoption replaced a different saved signer")
	}
}
