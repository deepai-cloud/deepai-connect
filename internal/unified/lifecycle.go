// Package unified ties the host overlay, Kubernetes lifecycle and coordinator
// into resumable per-host operations.
package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const defaultDir = "/var/lib/deepai-connect"
const servicesExtension = "cluster-services-v1"

func validateGatewayCertificate(raw []byte, hosts ...string) error {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("gateway requires a PEM server certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return errors.New("gateway certificate is not currently valid")
	}
	for _, host := range hosts {
		if err = cert.VerifyHostname(host); err != nil {
			return fmt.Errorf("gateway certificate does not cover %s", host)
		}
	}
	return nil
}

type installation struct {
	PendingEgressCleanup *egressCleanup         `json:"pendingEgressCleanup,omitempty"`
	PodRoutes            []netip.Prefix         `json:"podRoutes,omitempty"`
	GatewayInterface     string                 `json:"gatewayInterface,omitempty"`
	EgressSources        []netip.Prefix         `json:"egressSources,omitempty"`
	Version              int                    `json:"version"`
	Phase                string                 `json:"phase"`
	ClusterID            string                 `json:"clusterID"`
	Config               cluster.Config         `json:"config"`
	Services             cluster.ServiceConfig  `json:"services"`
	Invitation           *enrollment.Invitation `json:"invitation,omitempty"`
	RelayDomain          string                 `json:"relayDomain,omitempty"`
	PublicIP             string                 `json:"publicIP,omitempty"`
}

func writeJSON(path string, v any, exclusive bool) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return platform.WriteFile(path, append(b, '\n'), exclusive)
}
func saveInstallation(dir string, i *installation) error {
	return writeJSON(filepath.Join(dir, "unified.json"), i, false)
}
func loadInstallation(dir string) (*installation, error) {
	b, e := platform.ReadFile(filepath.Join(dir, "unified.json"))
	if e != nil {
		return nil, e
	}
	var i installation
	if json.Unmarshal(b, &i) != nil || i.Version != 1 || i.ClusterID == "" || i.Config.AgentStateDir != filepath.Join(dir, "network") || i.Config.DataDir != filepath.Join(dir, "cluster") {
		return nil, errors.New("invalid unified installation state; restore its backup")
	}
	return &i, nil
}
func hostRequired() error {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return errors.New("run the hub or worker inside a 64-bit Linux host or VM; use setup --hub USER@HOST for macOS or Windows SSH administration")
	}
	if os.Geteuid() != 0 {
		return errors.New("host network and systemd installation requires root")
	}
	return nil
}
func fresh(dir string) error {
	for _, name := range []string{"unified.json", "connect.json", "device.json"} {
		if _, e := os.Lstat(filepath.Join(dir, name)); e == nil {
			return fmt.Errorf("%s already contains %s; resume it or use a new directory", dir, name)
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}

func nodeFor(id *hostnet.Identity, name, role string, endpoints []netip.AddrPort) coordinator.Node {
	return coordinator.Node{MachineKey: id.Machine.Public().String(), NodeKey: id.Node.Public().String(), DiscoKey: id.Disco.Public().String(), Hostname: name, Role: role, Endpoints: endpoints, Cap: tailcfg.CurrentCapabilityVersion}
}
func seedState(id *hostnet.Identity, i *installation) (*hostnet.State, *coordinator.Node, error) {
	c := i.Config
	n := nodeFor(id, c.Name, "hub", []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(i.PublicIP), hostnet.DefaultPort)})
	n.ID = 1
	n.Addresses = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(c.OverlayIP), 32)}
	n.Created = time.Now().UTC()
	n.LastSeen = n.Created
	n.PodRoutes = slices.Clone(i.PodRoutes)
	n.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix(c.PodCIDR), netip.MustParsePrefix(c.ServiceCIDR)}
	n.ApprovedRoutes = append(n.ApprovedRoutes, i.PodRoutes...)
	n.Hostinfo = &tailcfg.Hostinfo{Hostname: c.Name, OS: "linux", RoutableIPs: n.ApprovedRoutes}
	s := &hostnet.State{Version: hostnet.StateVersion, ClusterID: i.ClusterID, CoordinatorURL: i.Services.PublicURL, Self: n.TailNode(), HostCIDR: netip.MustParsePrefix(c.HostCIDR), PodCIDR: netip.MustParsePrefix(c.PodCIDR), PodRoutes: slices.Clone(i.PodRoutes), ServiceCIDR: netip.MustParsePrefix(c.ServiceCIDR), PacketFilter: clusterPolicy(c.HostCIDR, c.PodCIDR, c.ServiceCIDR), DirectHubEndpoints: map[key.NodePublic][]netip.AddrPort{id.Node.Public(): n.Endpoints}, ListenPort: hostnet.DefaultPort, Interface: hostnet.DefaultInterface, UpdatedAt: n.Created, ExpiresAt: n.Created.Add(hostnet.CacheLifetime)}
	return s, &n, s.Validate(id, time.Now())
}
func clusterPolicy(host, pod, service string) []tailcfg.FilterRule {
	return []tailcfg.FilterRule{{SrcIPs: []string{host, pod}, DstPorts: []tailcfg.NetPortRange{{IP: host, Ports: tailcfg.PortRange{First: 0, Last: 65535}}, {IP: pod, Ports: tailcfg.PortRange{First: 0, Last: 65535}}, {IP: service, Ports: tailcfg.PortRange{First: 0, Last: 65535}}}}}
}
func stateFromGrant(g enrollment.Grant) *hostnet.State {
	direct := map[key.NodePublic][]netip.AddrPort{}
	for encoded, eps := range g.HubEndpoints {
		var k key.NodePublic
		if k.UnmarshalText([]byte(encoded)) == nil {
			direct[k] = eps
		}
	}
	now := time.Now().UTC()
	return &hostnet.State{Version: hostnet.StateVersion, ClusterID: g.Cluster.ID, CoordinatorURL: g.Cluster.URL, Self: g.Self, Peers: g.Peers, DERPMap: g.DERPMap, PacketFilter: g.Policy, HostCIDR: netip.MustParsePrefix(g.Cluster.HostCIDR), PodCIDR: netip.MustParsePrefix(g.Cluster.PodCIDR), ServiceCIDR: netip.MustParsePrefix(g.Cluster.ServiceCIDR), DirectHubEndpoints: direct, ListenPort: hostnet.DefaultPort, Interface: hostnet.DefaultInterface, UpdatedAt: now, ExpiresAt: now.Add(hostnet.CacheLifetime)}
}

func startAgent(ctx context.Context, i *installation) error {
	c := i.Config
	if strings.ContainsAny(c.ConnectBinary+c.AgentStateDir, "\r\n\x00%$") {
		return errors.New("unsupported systemd path")
	}
	quote := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
	unit := "# Managed by DeepAI Connect unified v1\n[Unit]\nDescription=DeepAI Connect host overlay\nWants=network-online.target\nAfter=network-online.target\nBefore=" + cluster.UnitName + "\n\n[Service]\nType=simple\nExecStart=" + quote(c.ConnectBinary) + " agent --dir " + quote(filepath.Dir(c.AgentStateDir)) + "\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=20\n\n[Install]\nWantedBy=multi-user.target\n"
	path := filepath.Join(c.SystemdDir, cluster.AgentUnitName)
	if prior, err := platform.ReadFile(path); err == nil && string(prior) != unit {
		return errors.New("agent systemd unit differs; restore the original installation path or explicitly migrate it")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := platform.WriteFile(path, []byte(unit), false); err != nil {
		return err
	}
	r := cluster.ExecRunner{}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", cluster.AgentUnitName}, {"start", cluster.AgentUnitName}} {
		if _, err := r.Run(ctx, nil, "systemctl", args...); err != nil {
			return err
		}
	}
	wait, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return hostnet.WaitReady(wait, c.AgentStateDir)
}

func resume(ctx context.Context, dir string, i *installation) error {
	unlock, err := platform.Lock(filepath.Join(defaultDir, "runtime-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	retryWorker := i.Phase == "cluster" && i.Config.Role == "worker"
	if i.Phase == "enrolling" {
		if err := enrollNetwork(ctx, dir, i); err != nil {
			return err
		}
	}
	if _, err := agentEnrollmentIdentity(dir, i); err != nil {
		return err
	}
	id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	snapshot, err := hostnet.LoadState(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	if err := snapshot.Validate(id, time.Now()); err != nil {
		return err
	}
	if i.PendingEgressCleanup != nil {
		if err := restartEgressConfiguration(ctx, dir, i); err != nil {
			return err
		}
	}
	if err := startAgent(ctx, i); err != nil {
		return err
	}
	if !i.Config.FirstHub && (i.Phase == "enrolling" || i.Phase == "network") {
		id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
		if err != nil {
			return err
		}
		identity, err := enrollment.LoadIdentity(dir)
		if err != nil {
			return err
		}
		state, err := hostnet.LoadState(i.Config.AgentStateDir)
		if err != nil {
			return err
		}
		n := nodeFor(id, i.Config.Name, i.Config.Role, state.Self.Endpoints)
		// Both directions must work before installing K3s. A failed attempt keeps
		// the invitation and keys, allowing exactly the same claim to resume.
		var peers []netip.Addr
		for _, p := range state.Peers {
			if slices.Contains(p.Tags, "tag:hub") {
				peers = append(peers, p.Addresses[0].Addr())
			}
		}
		if len(peers) == 0 {
			return errors.New("enrollment returned no reachable hub")
		}
		wait, cancel := context.WithTimeout(ctx, 90*time.Second)
		var peer netip.Addr
		for {
			for _, candidate := range peers {
				probe, done := context.WithTimeout(wait, 3*time.Second)
				err = hostnet.VerifyPeer(probe, i.Config.AgentStateDir, candidate)
				done()
				if err == nil {
					peer = candidate
					break
				}
			}
			if peer.IsValid() {
				break
			}
			select {
			case <-wait.Done():
				cancel()
				return errors.New("hub overlay is not reachable; resume after checking UDP/DERP paths")
			case <-time.After(2 * time.Second):
			}
		}
		cancel()
		grant, err := enrollment.Exchange(ctx, *i.Invitation, identity, n, "confirm")
		if err != nil {
			return err
		}
		i.Config.JoinToken = grant.Token
		i.Config.ServerURL = "https://" + peer.String() + ":6443"
		if !slices.Contains(grant.ServerURLs, i.Config.ServerURL) {
			return errors.New("reachable hub is absent from the authenticated Kubernetes grant")
		}
		i.Phase = "cluster"
		if err := saveInstallation(dir, i); err != nil {
			return err
		}
	}
	if retryWorker {
		if err := refreshPendingWorker(ctx, dir, i, nil, enrollment.Exchange); err != nil {
			return err
		}
	}
	m, err := cluster.New(i.Config, nil)
	if err != nil {
		return err
	}
	if err = m.Install(ctx); err != nil {
		return err
	}
	if err = updatePodRoutes(ctx, dir, i, m); err != nil {
		return err
	}
	if i.Config.FirstHub {
		if err = initializeServices(ctx, dir, i, m); err != nil {
			return err
		}
	} else {
		identity, err := enrollment.LoadIdentity(dir)
		if err != nil {
			return err
		}
		id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
		if err != nil {
			return err
		}
		_, err = enrollment.Exchange(ctx, *i.Invitation, identity, nodeFor(id, i.Config.Name, i.Config.Role, nil), "complete")
		if err != nil {
			return err
		}
		if i.Config.Role == "hub" {
			if err = addHub(ctx, dir, i, m); err != nil {
				return err
			}
		}
	}
	i.Phase = "ready"
	if err = saveInstallation(dir, i); err != nil {
		return err
	}
	return hostnet.Refresh(ctx, i.Config.AgentStateDir)
}

// A worker may remain in the cluster phase longer than its bootstrap token's
// 24-hour lifetime. Reconfirm the same signed membership, without replaying the
// invitation or changing the overlay allocation, before retrying Kubernetes.
func refreshPendingWorker(ctx context.Context, dir string, i *installation, runner cluster.Runner, exchange func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error)) error {
	if i.Phase != "cluster" || i.Config.Role != "worker" || i.Config.FirstHub {
		return nil
	}
	m, err := cluster.New(i.Config, runner)
	if err != nil {
		return err
	}
	saved, err := cluster.Load(i.Config.DataDir, runner)
	if err == nil {
		candidate := m.Config
		candidate.JoinToken = saved.Config.JoinToken
		before, _ := json.Marshal(saved.Config)
		after, _ := json.Marshal(candidate)
		if !bytes.Equal(before, after) || strings.SplitN(m.Config.JoinToken, "::", 2)[0] != strings.SplitN(saved.Config.JoinToken, "::", 2)[0] {
			return errors.New("pending worker configuration differs from its saved installation")
		}
		joined, err := saved.HasJoined(ctx)
		if err != nil {
			return err
		}
		if joined {
			// Installation can finish before the unified phase is committed. The
			// cluster's confirmed credential wins over an interrupted refresh.
			if i.Config.JoinToken != saved.Config.JoinToken {
				i.Config.JoinToken = saved.Config.JoinToken
				return saveInstallation(dir, i)
			}
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if i.Invitation == nil {
		return errors.New("missing saved worker enrollment")
	}
	// Recovery requires the original keys. Never create replacement identities
	// when a pending enrollment has lost either of its private key files.
	id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
	if err != nil {
		return fmt.Errorf("restore the original worker identity before resuming: %w", err)
	}
	signing, err := enrollment.LoadIdentity(dir)
	if err != nil {
		return fmt.Errorf("restore the original worker identity before resuming: %w", err)
	}
	state, err := hostnet.LoadState(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	if err = state.Validate(id, time.Now()); err != nil {
		return err
	}
	if state.ClusterID != i.ClusterID || state.CoordinatorURL != i.Invitation.URL || state.Self.Addresses[0].Addr().String() != i.Config.OverlayIP {
		return errors.New("worker overlay identity differs from its pending enrollment")
	}
	node := nodeFor(id, i.Config.Name, i.Config.Role, state.Self.Endpoints)
	grant, err := exchange(ctx, *i.Invitation, signing, node, "confirm")
	if err != nil {
		return err
	}
	if err = enrollment.ValidateGrant(*i.Invitation, node, grant, true); err != nil {
		return err
	}
	if grant.Self.Addresses[0].Addr().String() != i.Config.OverlayIP || grant.Cluster.HostCIDR != i.Config.HostCIDR || grant.Cluster.PodCIDR != i.Config.PodCIDR || grant.Cluster.ServiceCIDR != i.Config.ServiceCIDR || grant.Cluster.DesiredVoters != i.Config.DesiredVoters || !slices.Contains(grant.ServerURLs, i.Config.ServerURL) || strings.SplitN(grant.Token, "::", 2)[0] != strings.SplitN(i.Config.JoinToken, "::", 2)[0] {
		return errors.New("refreshed worker grant changes the saved cluster identity")
	}
	i.Config.JoinToken = grant.Token
	return saveInstallation(dir, i)
}
func enrollNetwork(ctx context.Context, dir string, i *installation) error {
	if i.Invitation == nil {
		return errors.New("missing saved invitation")
	}
	id, err := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	k, err := enrollment.Identity(dir)
	if err != nil {
		return err
	}
	var endpoints []netip.AddrPort
	if i.PublicIP != "" {
		ip, e := netip.ParseAddr(i.PublicIP)
		if e != nil {
			return e
		}
		endpoints = []netip.AddrPort{netip.AddrPortFrom(ip, hostnet.DefaultPort)}
	}
	g, err := enrollment.Exchange(ctx, *i.Invitation, k, nodeFor(id, i.Config.Name, i.Config.Role, endpoints), "enroll")
	if err != nil {
		return err
	}
	s := stateFromGrant(g)
	if err = s.Validate(id, time.Now()); err != nil {
		return err
	}
	if err = hostnet.SaveState(i.Config.AgentStateDir, s); err != nil {
		return err
	}
	i.Config.OverlayIP = g.Self.Addresses[0].Addr().String()
	i.Config.HostCIDR = g.Cluster.HostCIDR
	i.Config.PodCIDR = g.Cluster.PodCIDR
	i.Config.ServiceCIDR = g.Cluster.ServiceCIDR
	i.Config.DesiredVoters = g.Cluster.DesiredVoters
	i.Config.ConnectImage = g.Cluster.Image
	i.Phase = "network"
	return saveInstallation(dir, i)
}
func updatePodRoutes(ctx context.Context, dir string, i *installation, m *cluster.Manager) error {
	routes, err := awaitPodRoutes(ctx, i, m)
	if err != nil {
		return err
	}
	pool := netip.MustParsePrefix(i.Config.PodCIDR)
	for _, p := range routes {
		if !pool.Contains(p.Addr()) || p.Bits() < pool.Bits() {
			return errors.New("assigned pod route is outside the cluster pod network")
		}
	}
	i.PodRoutes = routes
	if err = saveInstallation(dir, i); err != nil {
		return err
	}
	s, err := hostnet.LoadState(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	s.PodRoutes = routes
	s.UpdatedAt = time.Now().UTC()
	return hostnet.Update(ctx, i.Config.AgentStateDir, s)
}

// A kubelet can report Ready before the node controller allocates its pod CIDR.
// Wait for that allocation before publishing routes or starting services that
// need pod return paths. Invalid allocations and API failures remain errors.
func awaitPodRoutes(ctx context.Context, i *installation, m *cluster.Manager) ([]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		raw, err := m.Kubectl(ctx, nil, "get", "node", i.Config.Name, "-o", "json")
		if err != nil {
			return nil, err
		}
		var n struct {
			Spec struct {
				PodCIDR  string   `json:"podCIDR"`
				PodCIDRs []string `json:"podCIDRs"`
			}
		}
		if json.Unmarshal(raw, &n) != nil {
			return nil, errors.New("invalid Kubernetes node response")
		}
		if n.Spec.PodCIDR != "" || len(n.Spec.PodCIDRs) != 0 {
			return parsePodRoutes(n.Spec.PodCIDR, n.Spec.PodCIDRs)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("await Kubernetes pod CIDR assignment for %s: %w", i.Config.Name, ctx.Err())
		case <-tick.C:
		}
	}
}

func initializeServices(ctx context.Context, dir string, i *installation, m *cluster.Manager) error {
	k, err := localKube(ctx, m)
	if err != nil {
		return err
	}
	existing, err := k.store.Load(ctx)
	if err != nil {
		return err
	}
	if _, ok := existing.Extensions[enrollment.Extension]; ok {
		srv, err := coordinator.New(ctx, coordinator.Config{Store: k.store})
		if err != nil {
			return err
		}
		defer srv.Close()
		if err = refreshFirstHubRegistration(ctx, i, srv.Update); err != nil {
			return err
		}
		if err = saveInstallation(dir, i); err != nil {
			return err
		}
		return m.ApplyRegisteredServices(ctx)
	}
	if i.Phase == "ready" {
		return errors.New("durable cluster registry is missing; restore etcd rather than recreating identities")
	}
	token, err := m.JoinToken(ctx)
	if err != nil {
		return err
	}
	admin, err := coordinator.NewToken()
	if err != nil {
		return err
	}
	relay := key.NewNode()
	relayText, _ := relay.MarshalText()
	services := i.Services
	services.BootstrapSecret = map[string]string{"server-token": token, "admin-token": admin, "derp-key": string(relayText)}
	if err = m.ReconcileServices(ctx, services); err != nil {
		return err
	}
	srv, err := coordinator.New(ctx, coordinator.Config{Store: k.store})
	if err != nil {
		return err
	}
	defer srv.Close()
	id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	_, node, err := seedState(id, i)
	if err != nil {
		return err
	}
	err = srv.Update(ctx, func(s *coordinator.State) error {
		if _, exists := s.Extensions[enrollment.Extension]; exists {
			r, e := enrollment.ReadRegistry(s)
			if e != nil {
				return e
			}
			if r.Cluster.ID != i.ClusterID {
				return errors.New("cluster identity conflicts with local state")
			}
			return nil
		}
		s.Network = i.Config.HostCIDR
		s.Policy = clusterPolicy(i.Config.HostCIDR, i.Config.PodCIDR, i.Config.ServiceCIDR)
		if err := coordinator.AllocateNode(s, node); err != nil {
			return err
		}
		if err := enrollment.ApprovePodRoutes(s, node.MachineKey, i.Config.PodCIDR, i.PodRoutes); err != nil {
			return err
		}
		c := enrollment.Cluster{ID: i.ClusterID, URL: i.Services.PublicURL, HostCIDR: i.Config.HostCIDR, PodCIDR: i.Config.PodCIDR, ServiceCIDR: i.Config.ServiceCIDR, DesiredVoters: i.Config.DesiredVoters, Image: i.Services.Image}
		r := enrollment.Registry{Cluster: c, Invites: map[string]*enrollment.Invite{}, Members: map[string]*enrollment.Member{node.MachineKey: {Name: i.Config.Name, Role: "hub", Voter: true, Ready: true}}}
		if err := enrollment.WriteRegistry(s, r); err != nil {
			return err
		}
		return storeServices(s, i.Services)
	})
	if err != nil {
		return err
	}
	return m.WaitServicesReady(ctx, services)
}

// refreshFirstHubRegistration reconciles the Kubernetes allocation refreshed by
// updatePodRoutes without recreating membership or overwriting shared services.
// All authorization and route replacement occur against the same CAS revision.
func refreshFirstHubRegistration(ctx context.Context, i *installation, update func(context.Context, func(*coordinator.State) error) error) error {
	id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	machine := id.Machine.Public().String()
	var services cluster.ServiceConfig
	err = update(ctx, func(s *coordinator.State) error {
		r, err := enrollment.ReadRegistry(s)
		if err != nil {
			return err
		}
		if r.Cluster.ID != i.ClusterID || r.Cluster.HostCIDR != i.Config.HostCIDR || r.Cluster.PodCIDR != i.Config.PodCIDR || r.Cluster.ServiceCIDR != i.Config.ServiceCIDR {
			return errors.New("cluster identity or address ranges conflict with local state")
		}
		n, member := s.Nodes[machine], r.Members[machine]
		address, err := netip.ParseAddr(i.Config.OverlayIP)
		if err != nil || !i.Config.FirstHub || i.Config.Role != "hub" || !i.Config.Voter || n == nil || n.Revoked || n.MachineKey != machine || n.NodeKey != id.Node.Public().String() || n.DiscoKey != id.Disco.Public().String() || n.Hostname != i.Config.Name || n.Role != "hub" || !slices.Equal(n.Addresses, []netip.Prefix{netip.PrefixFrom(address, 32)}) || member == nil || member.Name != i.Config.Name || member.Role != "hub" || !member.Voter || !member.Ready {
			return errors.New("first hub membership conflicts with the persisted local identity")
		}
		if !n.KeyExpiry.IsZero() && !time.Now().Before(n.KeyExpiry) {
			return errors.New("first hub network identity has expired")
		}
		var current cluster.ServiceConfig
		if err := json.Unmarshal(s.Extensions[servicesExtension], &current); err != nil {
			return errors.New("cluster service registry is missing or invalid")
		}
		services = current
		return enrollment.ApprovePodRoutes(s, machine, r.Cluster.PodCIDR, i.PodRoutes)
	})
	if err == nil {
		i.Services = services
	}
	return err
}

func storeServices(s *coordinator.State, services cluster.ServiceConfig) error {
	if len(services.TLSCertificate) > 0 && services.TLSSecretName == "" {
		services.TLSSecretName = "connect-gateway-tls"
	}
	services.BootstrapSecret = nil
	services.TLSKey = nil
	services.TLSCertificate = nil
	raw, err := json.Marshal(services)
	if err != nil {
		return err
	}
	s.Extensions[servicesExtension] = raw
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{}}
	for j, h := range services.Hubs {
		id := 900 + j
		dm.Regions[id] = &tailcfg.DERPRegion{RegionID: id, RegionCode: h.Name, RegionName: "Connect " + h.Name, Nodes: []*tailcfg.DERPNode{{Name: h.Name, RegionID: id, HostName: h.Hostname, IPv4: h.PublicIP, STUNPort: 3478, DERPPort: 443}}}
	}
	s.DERPMap = dm
	return nil
}
func addHub(ctx context.Context, dir string, i *installation, m *cluster.Manager) error {
	k, err := localKube(ctx, m)
	if err != nil {
		return err
	}
	srv, err := coordinator.New(ctx, coordinator.Config{Store: k.store})
	if err != nil {
		return err
	}
	defer srv.Close()
	err = srv.Update(ctx, func(s *coordinator.State) error {
		var services cluster.ServiceConfig
		if json.Unmarshal(s.Extensions[servicesExtension], &services) != nil {
			return errors.New("missing cluster services configuration")
		}
		var tlsSecret struct{ Data map[string][]byte }
		if err := k.call(ctx, "GET", "/api/v1/namespaces/"+services.Namespace+"/secrets/"+services.TLSSecretName, nil, &tlsSecret); err != nil {
			return err
		}
		if err := validateGatewayCertificate(tlsSecret.Data["tls.crt"], i.RelayDomain); err != nil {
			return err
		}
		for _, h := range services.Hubs {
			if h.Name == i.Config.Name {
				i.Services = services
				return nil
			}
		}
		for _, h := range services.Hubs {
			if h.Hostname == i.RelayDomain {
				return errors.New("relay hostname is already assigned")
			}
		}
		services.Hubs = append(services.Hubs, cluster.HubEndpoint{Name: i.Config.Name, Hostname: i.RelayDomain, PublicIP: i.PublicIP})
		id, e := hostnet.LoadIdentity(i.Config.AgentStateDir)
		if e != nil {
			return e
		}
		n := s.Nodes[id.Machine.Public().String()]
		if n == nil {
			return errors.New("joined hub is missing network membership")
		}
		for _, p := range []netip.Prefix{netip.MustParsePrefix(i.Config.PodCIDR), netip.MustParsePrefix(i.Config.ServiceCIDR)} {
			if !slices.Contains(n.ApprovedRoutes, p) {
				n.ApprovedRoutes = append(n.ApprovedRoutes, p)
			}
		}
		i.Services = services
		return storeServices(s, services)
	})
	if err != nil {
		return err
	}
	if err = saveInstallation(dir, i); err != nil {
		return err
	}
	return m.ApplyRegisteredServices(ctx)
}
