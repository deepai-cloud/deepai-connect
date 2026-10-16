package unified

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"tailscale.com/tailcfg"
)

func runAgentCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "private unified installation directory")
	if e := parse(fs, args); e != nil {
		return e
	}
	if e := hostRequired(); e != nil {
		return e
	}
	absolute, e := filepath.Abs(*dir)
	if e != nil {
		return e
	}
	*dir = absolute
	i, e := loadInstallation(*dir)
	if e != nil {
		return e
	}
	if e = finishEgressCleanup(ctx, *dir, i); e != nil {
		return e
	}
	if i.GatewayInterface != "" {
		if i.Config.Role != "hub" {
			return errors.New("only a hub may provide Internet egress")
		}
		if e = hostnet.ConfigureGateway(ctx, i.GatewayInterface, []netip.Prefix{netip.MustParsePrefix(i.Config.HostCIDR), netip.MustParsePrefix(i.Config.PodCIDR)}); e != nil {
			return e
		}
	}
	k, e := agentEnrollmentIdentity(*dir, i)
	if e != nil {
		return e
	}
	snapshot, e := hostnet.LoadState(i.Config.AgentStateDir)
	if e != nil {
		return e
	}
	snapshot = snapshot.WithEgressConfig(i.EgressSources, i.GatewayInterface != "")
	snapshot.PodRoutes = slices.Clone(i.PodRoutes)
	if e = hostnet.SaveState(i.Config.AgentStateDir, snapshot); e != nil {
		return e
	}
	// Flannel's IPv4 wildcard socket can receive underlay packets even with
	// its lower device set to deepai0. Guard the local listener before either
	// overlay readiness or K3s startup, and keep the guard across agent stops.
	if e = hostnet.ConfigureVXLANBoundary(ctx, snapshot.Interface); e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	fetch := func(ctx context.Context, id *hostnet.Identity, s *hostnet.State, ep []netip.AddrPort) (*tailcfg.MapResponse, error) {
		return fetchMapWithGateway(ctx, id, s, ep, i.GatewayInterface != "")
	}
	go func() {
		errs <- hostnet.Run(ctx, i.Config.AgentStateDir, hostnet.Options{Fetch: fetch, Logf: log.Printf})
	}()
	wait, cancelWait := context.WithTimeout(ctx, time.Minute)
	defer cancelWait()
	if e = hostnet.WaitReady(wait, i.Config.AgentStateDir); e != nil {
		return e
	}
	state, e := hostnet.LoadState(i.Config.AgentStateDir)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", net.JoinHostPort(state.Self.Addresses[0].Addr().String(), "9444"))
	if e != nil {
		return e
	}
	server := &http.Server{Handler: enrollment.ProbeHandler(k), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	defer server.Close()
	go func() { errs <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		return nil
	case e := <-errs:
		return e
	}
}

func agentEnrollmentIdentity(dir string, i *installation) (ed25519.PrivateKey, error) {
	// First-hub bootstrap has no enrollment exchange to create its probe key.
	// Every other agent starts after enrollment already committed that key.
	if i.Config.FirstHub && i.Phase == "network" {
		return enrollment.Identity(dir)
	}
	k, err := enrollment.LoadIdentity(dir)
	if err != nil {
		return nil, fmt.Errorf("restore the original enrollment key before starting the agent: %w", err)
	}
	return k, nil
}

func fetchMap(ctx context.Context, id *hostnet.Identity, s *hostnet.State, endpoints []netip.AddrPort) (*tailcfg.MapResponse, error) {
	return fetchMapWithGateway(ctx, id, s, endpoints, false)
}
func fetchMapWithGateway(ctx context.Context, id *hostnet.Identity, s *hostnet.State, endpoints []netip.AddrPort, gateway bool) (*tailcfg.MapResponse, error) {
	if s.CoordinatorURL == "" {
		return nil, errors.New("no coordinator configured")
	}
	for _, ep := range s.DirectHubEndpoints[s.Self.Key] {
		if !slices.Contains(endpoints, ep) {
			endpoints = append(endpoints, ep)
		}
	}
	endpoints = s.UnderlayEndpoints(endpoints)
	hostname := strings.Split(strings.TrimSuffix(s.Self.Name, "."), ".")[0]
	hostname = strings.TrimSuffix(hostname, "-"+strconv.FormatInt(int64(s.Self.ID), 10))
	if s.Self.Hostinfo.Valid() && s.Self.Hostinfo.Hostname() != "" {
		hostname = s.Self.Hostinfo.Hostname()
	}
	hi := &tailcfg.Hostinfo{Hostname: hostname, OS: "linux", RoutableIPs: slices.Clone(s.PodRoutes)}
	if s.Self.Hostinfo.Valid() {
		hi.NetInfo = s.Self.Hostinfo.AsStruct().NetInfo.Clone()
	}
	if slices.Contains(s.Self.Tags, "tag:hub") {
		for _, route := range []netip.Prefix{s.PodCIDR, s.ServiceCIDR} {
			if !slices.Contains(hi.RoutableIPs, route) {
				hi.RoutableIPs = append(hi.RoutableIPs, route)
			}
		}
	}
	if gateway {
		hi.RoutableIPs = append(hi.RoutableIPs, netip.MustParsePrefix("0.0.0.0/0"))
	}
	client := coordinator.Client{ServerURL: s.CoordinatorURL, MachineKey: id.Machine}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return client.Map(bounded, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: id.Node.Public(), DiscoKey: id.Disco.Public(), Endpoints: endpoints, Hostinfo: hi, Stream: false, ReadOnly: false})
}
func runCoordinatorCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("coordinator", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "HTTP listener behind the TLS gateway")
	namespace := fs.String("namespace", "deepai-system", "Kubernetes namespace")
	credentials := fs.String("bootstrap-secret-dir", "/etc/deepai/credentials", "projected enrollment Secret directory")
	if e := parse(fs, args); e != nil {
		return e
	}
	store, e := coordinator.InClusterStore(*namespace)
	if e != nil {
		return e
	}
	admin, e := os.ReadFile(filepath.Join(*credentials, "admin-token"))
	if e != nil {
		return errors.New("missing coordinator administration Secret")
	}
	control, e := coordinator.New(ctx, coordinator.Config{Store: store, AdminToken: strings.TrimSpace(string(admin))})
	if e != nil {
		return e
	}
	defer control.Close()
	broker := enrollment.Broker{Store: store, Update: control.Update, Backend: clusterBackend{kube: kube{store}, credentialsDir: *credentials}}
	mux := http.NewServeMux()
	mux.Handle("/v1/", broker.Handler())
	mux.Handle("/", control.Handler())
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return e
	}
	defer listener.Close()
	ctx, cancelInfrastructure := context.WithCancel(ctx)
	defer cancelInfrastructure()
	go cluster.RunInfrastructureReconciler(ctx, infrastructureAPI(store), log.Printf)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case e := <-done:
		return e
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}
