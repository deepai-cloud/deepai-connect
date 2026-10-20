package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// A bundle travels only over SSH stdin, never through command arguments or a
// shell-created temporary file. Paths in the spec remain portable Git inputs.
type cloudBundle struct {
	Cloud       *cloudconfig.Cloud   `json:"cloud"`
	Policy      []tailcfg.FilterRule `json:"policy"`
	Certificate []byte               `json:"certificate,omitempty"`
	Key         []byte               `json:"key,omitempty"`
}

const maxCloudBundleSize = 4 << 20

func decodeCloudBundle(in io.Reader) (*cloudBundle, error) {
	// Read one byte past the limit: a LimitReader alone can turn truncated
	// trailing input into an apparent EOF after an otherwise valid object.
	raw, err := io.ReadAll(io.LimitReader(in, maxCloudBundleSize+1))
	if err != nil || len(raw) > maxCloudBundleSize {
		return nil, errors.New("deployment bundle is unreadable or exceeds 4 MiB")
	}
	var b *cloudBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil || b == nil || dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid deployment bundle")
	}
	if err := validateCloudBundle(b); err != nil {
		return nil, err
	}
	return b, nil
}

var cloudProcess = func(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hub SSH command failed: %w", err)
	}
	return nil
}

func cloudSSHArgs(hub string, command ...string) ([]string, error) {
	if err := cloudconfig.ValidateSSH(hub); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(hub, "root@") {
		command = append([]string{"sudo", "-n", "--"}, command...)
	}
	quoted := make([]string, len(command))
	for j, arg := range command {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return nil, errors.New("SSH command arguments cannot contain NUL or line breaks")
		}
		quoted[j] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return append([]string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-T", hub}, strings.Join(quoted, " ")), nil
}

func readCloudFile(base, name string) ([]byte, error) {
	if !filepath.IsAbs(name) {
		name = filepath.Join(filepath.Dir(base), name)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("cloud input is unreadable or larger than 1 MiB")
	}
	return data, nil
}

func loadCloudBundle(path string, credentials bool) (*cloudBundle, error) {
	c, err := cloudconfig.Load(path)
	if err != nil {
		return nil, err
	}
	b := &cloudBundle{Cloud: c}
	if c.Network.PacketPolicyFile != "" {
		raw, err := readCloudFile(path, c.Network.PacketPolicyFile)
		if err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &b.Policy) != nil || b.Policy == nil {
			return nil, errors.New("packetPolicyFile must contain a JSON FilterRule array")
		}
	}
	if credentials && c.Bootstrap.TLSCertFile != "" {
		b.Certificate, err = readCloudFile(path, c.Bootstrap.TLSCertFile)
		if err != nil {
			return nil, err
		}
		b.Key, err = readCloudFile(path, c.Bootstrap.TLSKeyFile)
		if err != nil {
			return nil, err
		}
	}
	return b, validateCloudBundle(b)
}

func validateCloudBundle(b *cloudBundle) error {
	if b.Cloud == nil {
		return errors.New("missing cloud definition")
	}
	if err := cloudconfig.Validate(b.Cloud); err != nil {
		return err
	}
	if b.Cloud.Network.PacketPolicyFile != "" && b.Policy == nil {
		return errors.New("missing declared packet policy")
	}
	if b.Policy != nil {
		if _, err := filter.MatchesFromFilterRules(b.Policy); err != nil {
			return fmt.Errorf("invalid packet policy: %w", err)
		}
	}
	if (len(b.Certificate) == 0) != (len(b.Key) == 0) {
		return errors.New("TLS certificate and key must be supplied together")
	}
	return nil
}

func cloudCommand(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	file := fs.String("file", "cloud.yaml", "declarative cloud YAML")
	fs.StringVar(file, "f", "cloud.yaml", "declarative cloud YAML")
	local := fs.Bool("local", false, "operate on this hub instead of using its declared SSH connection")
	bundle := fs.Bool("bundle", false, "read a private deployment bundle from stdin (SSH transport)")
	dir := fs.String("dir", defaultDir, "hub installation directory")
	if err := parse(fs, args); err != nil {
		return err
	}
	var b *cloudBundle
	var err error
	if *bundle {
		if !*local {
			return errors.New("--bundle requires --local")
		}
		b, err = decodeCloudBundle(os.Stdin)
	} else {
		b, err = loadCloudBundle(*file, command == "apply")
	}
	if err != nil {
		return err
	}
	hub := b.Cloud.Nodes[b.Cloud.Bootstrap.Node]
	if !*local && hub.Connection.SSH != "" {
		remote, err := cloudSSHArgs(hub.Connection.SSH, "deepai-connect", command, "--local", "--bundle", "--dir", *dir)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return err
		}
		return cloudProcess(ctx, remote, bytes.NewReader(raw), os.Stdout, os.Stderr)
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	return applyCloudLocal(ctx, absolute, b, command == "plan", os.Stdout)
}

func validateCloudInstallation(i *installation, c *cloudconfig.Cloud) error {
	h := c.Nodes[c.Bootstrap.Node]
	if !i.Config.FirstHub || i.Config.Role != "hub" || i.Config.Name != c.Bootstrap.Node ||
		i.Config.HostCIDR != c.Network.HostCIDR || i.Config.PodCIDR != c.Network.PodCIDR ||
		i.Config.ServiceCIDR != c.Network.ServiceCIDR || i.Config.DesiredVoters != c.Bootstrap.Voters ||
		i.Services.PublicURL != "https://"+c.Network.Domain || i.Config.ConnectImage != c.Bootstrap.Image ||
		i.PublicIP != h.PublicIP || i.RelayDomain != h.RelayDomain {
		return errors.New("cloud bootstrap identity, endpoint, image or network differs from this installation; migrate explicitly")
	}
	return nil
}

func applyCloudLocal(ctx context.Context, dir string, b *cloudBundle, preview bool, out io.Writer) error {
	return applyCloudWithRuntime(ctx, dir, b, preview, out, cloudRuntime{
		requireHost: hostRequired,
		create: func(ctx context.Context, args []string, b *cloudBundle) error {
			return createOrJoinCloud(ctx, "create", args, b)
		},
		resume: resume,
		open:   openCloudHub,
		pull: func(ctx context.Context, dir string) error {
			return pullConfiguration(ctx, dir, enrollment.Exchange)
		},
	})
}

// The runtime boundary keeps host/process operations separate from the
// transaction and recovery flow. Tests exercise that flow with real persisted
// identities and coordinator CAS, without changing the test host's network.
type cloudRuntime struct {
	requireHost func() error
	create      func(context.Context, []string, *cloudBundle) error
	resume      func(context.Context, string, *installation) error
	open        func(context.Context, *installation) (cloudHub, error)
	pull        func(context.Context, string) error
}

type cloudHub interface {
	Load(context.Context) (*coordinator.State, error)
	Update(context.Context, func(*coordinator.State) error) error
	Prepare(context.Context, *installation) error
	Labels(context.Context) error
	Close()
}

type connectedCloudHub struct{ kube }

func openCloudHub(ctx context.Context, i *installation) (cloudHub, error) {
	m, err := cluster.New(i.Config, nil)
	if err != nil {
		return nil, err
	}
	k, err := localKube(ctx, m)
	if err != nil {
		return nil, err
	}
	return connectedCloudHub{k}, nil
}

func (h connectedCloudHub) Load(ctx context.Context) (*coordinator.State, error) {
	return h.store.Load(ctx)
}

func (h connectedCloudHub) Update(ctx context.Context, change func(*coordinator.State) error) error {
	srv, err := coordinator.New(ctx, coordinator.Config{Store: h.store})
	if err != nil {
		return err
	}
	defer srv.Close()
	return srv.Update(ctx, change)
}

func (h connectedCloudHub) Prepare(ctx context.Context, i *installation) error {
	m, err := cluster.New(i.Config, nil)
	if err != nil {
		return err
	}
	return m.ApplyRegisteredServices(ctx)
}

func (h connectedCloudHub) Labels(ctx context.Context) error {
	return reconcileCloudLabels(ctx, h.kube)
}
func (h connectedCloudHub) Close() {
	if h.store.Client != nil {
		h.store.Client.CloseIdleConnections()
	}
}

func applyCloudWithRuntime(ctx context.Context, dir string, b *cloudBundle, preview bool, out io.Writer, runtime cloudRuntime) error {
	if b == nil {
		return errors.New("missing cloud deployment bundle")
	}
	if err := validateCloudBundle(b); err != nil {
		return err
	}
	if !preview {
		if err := runtime.requireHost(); err != nil {
			return err
		}
	}
	i, err := loadInstallation(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := fresh(dir); err != nil {
			return err
		}
		if preview {
			fmt.Fprintf(out, "Create hub %s; network %s, pods %s, services %s.\n", b.Cloud.Bootstrap.Node, b.Cloud.Network.HostCIDR, b.Cloud.Network.PodCIDR, b.Cloud.Network.ServiceCIDR)
			printCloudNodes(out, b.Cloud, nil)
			fmt.Fprintln(out, "Requires installed Connect/K3s, DNS and TLS files. Workers join using invitations.")
			return nil
		}
		if len(b.Certificate) == 0 || len(b.Key) == 0 {
			return errors.New("initial hub creation requires bootstrap.tlsCertFile and bootstrap.tlsKeyFile")
		}
		temp, err := os.MkdirTemp("", "connect-cloud-tls-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(temp)
		cert, key := filepath.Join(temp, "tls.crt"), filepath.Join(temp, "tls.key")
		if err = platform.WriteFile(cert, b.Certificate, true); err != nil {
			return err
		}
		if err = platform.WriteFile(key, b.Key, true); err != nil {
			return err
		}
		c, h := b.Cloud, b.Cloud.Nodes[b.Cloud.Bootstrap.Node]
		create := []string{"--dir", dir, "--name", c.Bootstrap.Node, "--domain", c.Network.Domain,
			"--public-ip", h.PublicIP, "--relay-domain", h.RelayDomain, "--image", c.Bootstrap.Image,
			"--tls-cert", cert, "--tls-key", key, "--host-cidr", c.Network.HostCIDR,
			"--pod-cidr", c.Network.PodCIDR, "--service-cidr", c.Network.ServiceCIDR,
			"--voters", fmt.Sprint(c.Bootstrap.Voters)}
		if err = runtime.create(ctx, create, b); err != nil {
			return err
		}
		i, err = loadInstallation(dir)
	}
	if err != nil {
		return err
	}
	if err = validateCloudInstallation(i, b.Cloud); err != nil {
		return err
	}
	if i.Phase != "ready" {
		if preview {
			fmt.Fprintf(out, "Hub %s installation is incomplete (%s); apply resumes the same identity.\n", i.Config.Name, i.Phase)
			return nil
		}
		unlock, err := platform.Lock(dir)
		if err != nil {
			return err
		}
		i, err = loadInstallation(dir)
		if err == nil {
			err = validateCloudInstallation(i, b.Cloud)
		}
		if err == nil {
			err = runtime.resume(ctx, dir, i)
		}
		unlock()
		if err != nil {
			return err
		}
	}
	hub, err := runtime.open(ctx, i)
	if err != nil {
		return err
	}
	defer hub.Close()
	state, err := hub.Load(ctx)
	if err != nil {
		return err
	}
	// Check the saved keys before preparing any service resources. Repeat the
	// check inside CAS below, since the registry can change after this preview.
	if err = registerCloudHubSigner(dir, i, state); err != nil {
		return err
	}
	previous, err := enrollment.ReadRegistry(state)
	if err != nil {
		return err
	}
	revision, err := enrollment.ApplyCloud(state, b.Cloud, b.Policy)
	if err != nil {
		return err
	}
	if previous.Cloud != nil && previous.Cloud.Revision == revision {
		fmt.Fprintf(out, "Cloud %s is unchanged (%s).\n", b.Cloud.Name, revision)
	} else {
		fmt.Fprintf(out, "%s cloud %s (%s).\n", map[bool]string{true: "Plan", false: "Apply"}[preview], b.Cloud.Name, revision)
	}
	printCloudNodes(out, b.Cloud, &previous)
	if preview {
		return nil
	}
	unlock, err := platform.Lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	// The preview and external reads above did not hold the installation lock.
	// Reload now so an intervening local gateway/egress change is never lost
	// when we save the cloud adoption marker below.
	i, err = loadInstallation(dir)
	if err != nil {
		return err
	}
	if err = validateCloudInstallation(i, b.Cloud); err != nil {
		return err
	}
	if i.Phase != "ready" {
		return errors.New("hub installation changed during apply; resume and retry")
	}
	// Existing hubs need the current coordinator RBAC as well as newly saved
	// desired state. Reconcile the registered services without replacing keys.
	if err = hub.Prepare(ctx, i); err != nil {
		return fmt.Errorf("prepare cloud coordinator services: %w", err)
	}
	if err = hub.Update(ctx, func(s *coordinator.State) error {
		if err := registerCloudHubSigner(dir, i, s); err != nil {
			return err
		}
		_, err := enrollment.ApplyCloud(s, b.Cloud, b.Policy)
		return err
	}); err != nil {
		return err
	}
	// Marks adopted first hubs for periodic pulls too. Resume never reapplies
	// this bootstrap snapshot over an existing coordinator registry.
	i.BootstrapCloud, i.BootstrapPolicy = b.Cloud, b.Policy
	if err = saveInstallation(dir, i); err != nil {
		return fmt.Errorf("cloud saved; persist hub pull configuration: %w", err)
	}
	if err = runtime.pull(ctx, dir); err != nil {
		return fmt.Errorf("cloud saved; hub configuration pull pending: %w", err)
	}
	if err = hub.Labels(ctx); err != nil {
		return fmt.Errorf("cloud saved; node labels still pending (coordinator will retry): %w", err)
	}
	fmt.Fprintln(out, "Cloud saved. Agents pull configuration automatically; use enroll --node NAME for new devices.")
	return nil
}

func registerCloudHubSigner(dir string, i *installation, s *coordinator.State) error {
	r, err := enrollment.ReadRegistry(s)
	if err != nil {
		return err
	}
	id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	k, err := enrollment.LoadIdentity(dir)
	if err != nil {
		return err
	}
	machine := id.Machine.Public().String()
	n, m := s.Nodes[machine], r.Members[machine]
	address, addressErr := netip.ParseAddr(i.Config.OverlayIP)
	if r.Cluster.ID != i.ClusterID || n == nil || n.Revoked || n.NodeKey != id.Node.Public().String() ||
		n.MachineKey != machine || n.Hostname != i.Config.Name || n.Role != "hub" || !i.Config.FirstHub ||
		addressErr != nil || len(n.Addresses) != 1 || n.Addresses[0] != netip.PrefixFrom(address, 32) ||
		m == nil || m.Name != i.Config.Name || m.Role != "hub" || !m.Voter || !m.Ready {
		return errors.New("bootstrap hub membership differs from its persisted identity")
	}
	pub := k.Public().(ed25519.PublicKey)
	if len(m.PublicKey) != 0 && !bytes.Equal(m.PublicKey, pub) {
		return errors.New("bootstrap enrollment signer differs from registry")
	}
	m.PublicKey = pub
	return enrollment.WriteRegistry(s, r)
}

func printCloudNodes(out io.Writer, c *cloudconfig.Cloud, r *enrollment.Registry) {
	names := make([]string, 0, len(c.Nodes))
	for name := range c.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status := "awaiting enrollment"
		if r != nil {
			for _, m := range r.Members {
				if m.Name == name {
					status = "joining"
					if m.Ready {
						status = "enrolled"
					}
				}
			}
		}
		fmt.Fprintf(out, "  %s: %s, %s\n", name, c.Nodes[name].Role, status)
	}
}
