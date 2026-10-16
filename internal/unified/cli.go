package unified

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/buildinfo"
	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"github.com/deepai-cloud/deepai-connect/internal/relay"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

const Help = `Usage: deepai-connect COMMAND [flags]

Administer a cluster from macOS or Linux over SSH:
  setup --hub USER@HOST [--vm NAME]  Save access to an existing hub and optional local VM
  status                     Show the mesh, cluster nodes and local VM
  doctor                     Check mesh, services, API, nodes and system workloads
  nodes                      List cluster nodes
  containers                 List workload pods and their container readiness
  logs POD [-n NAMESPACE]     Read workload logs (kubectl logs options)
  kubectl ARGS...            Run kubectl through the configured hub
  kubeconfig export|install  Export or install a separate cluster context
  tunnel                     Forward the private API to localhost for local kubectl

Create or manage a Linux host on the private network:
  create --name NAME --domain DOMAIN --public-ip IP --relay-domain DNS --image IMAGE:TAG
         --tls-cert FILE --tls-key FILE [--voters 3|5]
  enroll --role worker|hub|client [--voter] --out FILE
  join --name NAME --invite FILE [--public-ip IP --relay-domain DNS]
  resume                     Restore the saved overlay, then resume K3s
  refresh                    Authenticate to the coordinator and replace an expired cache
  inspect                    Inspect local overlay and cluster services
  publish --hostname DNS --service NAMESPACE/NAME --port PORT
  route --node NAME --cidr CIDR [--revoke]
  policy --file FILE         Replace packet policy with JSON FilterRule array
  gateway --interface NAME   Offer this hub as an Internet gateway
  egress --source CIDR       Send this local pod prefix through a healthy gateway
  gateway|egress --disable   Withdraw the optional local gateway or source policy
  version                    Print the installed build version

Host state defaults to /var/lib/deepai-connect (--dir overrides).
Laptop access is saved in ~/.config/deepai-connect/client.json.
Hubs and workers run inside Linux; macOS workers use a Linux VM.
Install the pinned K3s binary before create/join. Use COMMAND --help for options.
Setup and operations: docs/unified-connect.md.
`

func parse(fs *flag.FlagSet, args []string) error {
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		if len(args) > 1 {
			return errors.New("use deepai-connect COMMAND --help for command options")
		}
		fmt.Print(Help)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Println(buildinfo.Version)
		return nil
	}
	var err error
	switch args[0] {
	case "agent":
		err = runAgentCommand(ctx, args[1:])
	case "agent-ready":
		fs := flag.NewFlagSet("agent-ready", flag.ContinueOnError)
		dir := fs.String("dir", defaultDir, "private installation directory")
		if err = parse(fs, args[1:]); err == nil {
			wait, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			err = hostnet.WaitReady(wait, filepath.Join(*dir, "network"))
		}
	case "gateway", "egress":
		err = configureEgress(ctx, args[0], args[1:])
	case "refresh":
		err = refreshCommand(ctx, args[1:])
	case "coordinator":
		err = runCoordinatorCommand(ctx, args[1:])
	case "relay":
		err = runRelayCommand(ctx, args[1:])
	case "create", "join":
		err = createOrJoin(ctx, args[0], args[1:])
	default:
		err = manage(ctx, args[0], args[1:])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}
func createOrJoin(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "private installation directory")
	name := fs.String("name", "", "unique lowercase node name")
	ip := fs.String("public-ip", "", "directly reachable hub IPv4 address")
	relayDomain := fs.String("relay-domain", "", "unique public DNS hostname for this hub relay")
	k3s := fs.String("k3s", "/usr/local/bin/k3s", "path to pinned K3s binary")
	var domain, image, invite, hostCIDR, podCIDR, serviceCIDR, tlsCert, tlsKey string
	var voters int
	if command == "create" {
		fs.StringVar(&domain, "domain", "", "public coordination hostname")
		fs.StringVar(&image, "image", "", "built Connect service image with explicit release tag or digest")
		fs.StringVar(&tlsCert, "tls-cert", "", "PEM certificate covering coordination, relay and application DNS names")
		fs.StringVar(&tlsKey, "tls-key", "", "private PEM key, installed into a Kubernetes Secret")
		fs.IntVar(&voters, "voters", 3, "desired number of etcd voters: 3 or 5")
		fs.StringVar(&hostCIDR, "host-cidr", coordinator.DefaultNetwork, "host overlay pool within 100.64.0.0/10")
		fs.StringVar(&podCIDR, "pod-cidr", "10.42.0.0/16", "distinct pod network")
		fs.StringVar(&serviceCIDR, "service-cidr", "10.43.0.0/16", "distinct service network")
	} else {
		fs.StringVar(&invite, "invite", "", "private Connect invitation file")
	}
	if e := parse(fs, args); e != nil {
		return e
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	absolute, e := filepath.Abs(*dir)
	if e != nil {
		return e
	}
	*dir = absolute
	if e = hostRequired(); e != nil {
		return e
	}
	for _, binary := range []string{"ip", "iptables", "sysctl", "systemctl", *k3s} {
		if _, e = exec.LookPath(binary); e != nil {
			return fmt.Errorf("required host executable %s is unavailable", binary)
		}
	}
	unlock, e := platform.Lock(*dir)
	if e != nil {
		return e
	}
	defer unlock()
	if e = fresh(*dir); e != nil {
		return e
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	executable, e = filepath.EvalSymlinks(executable)
	if e != nil {
		return e
	}
	i := &installation{Version: 1, Phase: "enrolling", RelayDomain: *relayDomain, PublicIP: *ip, Config: cluster.Config{Name: *name, Role: "hub", K3sBinary: *k3s, ConnectBinary: executable, DataDir: filepath.Join(*dir, "cluster"), AgentStateDir: filepath.Join(*dir, "network"), SystemdDir: "/etc/systemd/system", OverlayInterface: hostnet.DefaultInterface}}
	if command == "create" {
		if !cluster.ValidDomain(domain) {
			return errors.New("--domain must be a lowercase public DNS hostname")
		}
		host, e := netip.ParsePrefix(hostCIDR)
		if e != nil || !host.Addr().Is4() || host != host.Masked() || host.Bits() < 10 || !netip.MustParsePrefix(coordinator.DefaultNetwork).Contains(host.Addr()) {
			return errors.New("host CIDR must be canonical and inside 100.64.0.0/10")
		}
		clusterID, e := coordinator.NewToken()
		if e != nil {
			return e
		}
		i.ClusterID = clusterID
		i.Config.FirstHub = true
		i.Config.Voter = true
		i.Config.DesiredVoters = voters
		i.Config.OverlayIP = host.Addr().Next().String()
		i.Config.HostCIDR = hostCIDR
		i.Config.PodCIDR = podCIDR
		i.Config.ServiceCIDR = serviceCIDR
		i.Config.ConnectImage = image
		m, e := cluster.New(i.Config, nil)
		if e != nil {
			return e
		}
		i.Config = m.Config
		i.Services = cluster.ServiceConfig{Namespace: cluster.Namespace, Image: image, PublicURL: "https://" + domain, Hubs: []cluster.HubEndpoint{{Name: *name, Hostname: *relayDomain, PublicIP: *ip}}}
		if tlsCert == "" || tlsKey == "" {
			return errors.New("create requires --tls-cert and --tls-key for a shared gateway identity on all hubs")
		}
		i.Services.TLSCertificate, e = platform.ReadFile(tlsCert)
		if e != nil {
			return e
		}
		i.Services.TLSKey, e = platform.ReadFile(tlsKey)
		if e != nil {
			return e
		}
		i.Services.TLSSecretName = "connect-gateway-tls"
		if e = validateGatewayCertificate(i.Services.TLSCertificate, domain, *relayDomain); e != nil {
			return e
		}
		if _, e = cluster.GenerateServices(i.Services); e != nil {
			return e
		}
		i.Phase = "network"
	} else {
		inv, e := enrollment.ReadInvitation(invite)
		if e != nil {
			return e
		}
		i.Invitation = &inv
		i.ClusterID = inv.ClusterID
		i.Config.Role = inv.Role
		i.Config.Voter = inv.Voter
	}
	if i.Config.Role == "hub" {
		public, e := netip.ParseAddr(*ip)
		if e != nil || !public.Is4() || !public.IsGlobalUnicast() || public.IsPrivate() || netip.MustParsePrefix(coordinator.DefaultNetwork).Contains(public) {
			return errors.New("hubs require a directly reachable public IPv4 address")
		}
		if !cluster.ValidDomain(*relayDomain) {
			return errors.New("hubs require --relay-domain with a public DNS hostname")
		}
	}
	if command == "create" {
		id, e := hostnet.LoadOrCreateIdentity(i.Config.AgentStateDir)
		if e != nil {
			return e
		}
		s, _, e := seedState(id, i)
		if e != nil {
			return e
		}
		if e = hostnet.SaveState(i.Config.AgentStateDir, s); e != nil {
			return e
		}
	}
	if e = saveInstallation(*dir, i); e != nil {
		return e
	}
	if e = resume(ctx, *dir, i); e != nil {
		return fmt.Errorf("installation saved; run deepai-connect resume --dir %s after resolving: %w", *dir, e)
	}
	fmt.Printf("%s %s is ready at %s.\n", i.Config.Role, i.Config.Name, i.Config.OverlayIP)
	return nil
}

func manage(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "private installation directory")
	var role, out, hostname, service, file, node, cidr string
	var voter, revoke bool
	var port int
	var ttl time.Duration
	switch command {
	case "enroll":
		fs.StringVar(&role, "role", "worker", "worker, hub or native client")
		fs.BoolVar(&voter, "voter", false, "authorize an etcd voter hub")
		fs.StringVar(&out, "out", "", "new private invitation file")
		fs.DurationVar(&ttl, "ttl", time.Hour, "invitation lifetime, maximum 24h")
	case "publish":
		fs.StringVar(&hostname, "hostname", "", "public application DNS hostname")
		fs.StringVar(&service, "service", "", "namespace/service")
		fs.IntVar(&port, "port", 80, "service port")
	case "policy":
		fs.StringVar(&file, "file", "", "JSON packet filter rules")
	case "route":
		fs.StringVar(&node, "node", "", "registered node hostname")
		fs.StringVar(&cidr, "cidr", "", "approved advertised prefix")
		fs.BoolVar(&revoke, "revoke", false, "remove route approval")
	case "resume", "inspect":
	default:
		return fmt.Errorf("unknown command %q; run deepai-connect --help", command)
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	*dir = absolute
	if command == "enroll" {
		if out == "" {
			return errors.New("enroll requires --out")
		}
		if _, e := os.Lstat(out); e == nil {
			return errors.New("invitation output already exists")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	unlock, err := platform.Lock(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	i, err := loadInstallation(*dir)
	if err != nil {
		return err
	}
	if command == "resume" {
		if err := hostRequired(); err != nil {
			return err
		}
		return resume(ctx, *dir, i)
	}
	if command == "inspect" {
		fmt.Printf("%s %s: phase=%s address=%s voter=%t\n", i.Config.Role, i.Config.Name, i.Phase, i.Config.OverlayIP, i.Config.Voter)
		s, e := hostnet.AgentStatus(ctx, i.Config.AgentStateDir)
		if e != nil {
			return e
		}
		fmt.Printf("overlay ready=%t peers=%d last-sync=%s cache-expires=%s\n", s.Ready, s.Peers, s.LastSync.Format(time.RFC3339), s.ExpiresAt.Format(time.RFC3339))
		return nil
	}
	if i.Config.Role != "hub" {
		return errors.New("cluster administration requires a hub")
	}
	m, err := cluster.New(i.Config, nil)
	if err != nil {
		return err
	}
	k, err := localKube(ctx, m)
	if err != nil {
		return err
	}
	srv, err := coordinator.New(ctx, coordinator.Config{Store: k.store})
	if err != nil {
		return err
	}
	defer srv.Close()
	switch command {
	case "enroll":
		if role == "client" {
			if voter {
				return errors.New("native client cannot vote")
			}
			if ttl <= 0 || ttl > 24*time.Hour {
				return errors.New("invitation lifetime must be between zero and 24h")
			}
			token, e := srv.CreateInvitation(ctx, coordinator.Invitation{Role: "client", UsesRemaining: 1, Expires: time.Now().Add(ttl)})
			if e != nil {
				return e
			}
			return platform.WriteFile(out, []byte(token+"\n"), true)
		}
		broker := enrollment.Broker{Store: k.store, Update: srv.Update}
		inv, e := broker.Invite(ctx, role, voter, ttl)
		if e != nil {
			return e
		}
		if e = writeJSON(out, inv, true); e != nil {
			return e
		}
		fmt.Printf("One-use %s invitation saved to %s.\n", role, out)
		return nil
	case "policy":
		data, e := platform.ReadFile(file)
		if e != nil {
			return e
		}
		var rules []tailcfg.FilterRule
		if json.Unmarshal(data, &rules) != nil || rules == nil {
			return errors.New("policy must be a JSON array of Tailscale FilterRule objects")
		}
		if _, e := filter.MatchesFromFilterRules(rules); e != nil {
			return fmt.Errorf("invalid packet policy: %w", e)
		}
		return srv.Update(ctx, func(s *coordinator.State) error { s.Policy = rules; return nil })
	case "route":
		prefix, e := netip.ParsePrefix(cidr)
		if e != nil || prefix != prefix.Masked() {
			return errors.New("route CIDR must be canonical")
		}
		return srv.Update(ctx, func(s *coordinator.State) error {
			host, e := netip.ParsePrefix(s.Network)
			if e != nil {
				return e
			}
			if prefix.Overlaps(host) && prefix.Bits() != 0 {
				return errors.New("route cannot overlap host identities")
			}
			var found *coordinator.Node
			for _, n := range s.Nodes {
				if n.Hostname == node {
					if found != nil {
						return errors.New("ambiguous node name")
					}
					found = n
				}
			}
			if found == nil || found.Revoked {
				return errors.New("node not found")
			}
			found.ApprovedRoutes = slices.DeleteFunc(found.ApprovedRoutes, func(p netip.Prefix) bool { return p == prefix })
			if !revoke {
				found.ApprovedRoutes = append(found.ApprovedRoutes, prefix)
			}
			return nil
		})
	case "publish":
		parts := strings.Split(service, "/")
		if len(parts) != 2 {
			return errors.New("service must be namespace/name")
		}
		current, e := k.store.Load(ctx)
		if e != nil {
			return e
		}
		var serviceConfig cluster.ServiceConfig
		if json.Unmarshal(current.Extensions[servicesExtension], &serviceConfig) != nil {
			return errors.New("missing service configuration")
		}
		var tlsSecret struct{ Data map[string][]byte }
		if e = k.call(ctx, "GET", "/api/v1/namespaces/"+serviceConfig.Namespace+"/secrets/"+serviceConfig.TLSSecretName, nil, &tlsSecret); e != nil {
			return e
		}
		if e = validateGatewayCertificate(tlsSecret.Data["tls.crt"], hostname); e != nil {
			return e
		}
		if !slices.Contains(serviceConfig.Apps, hostname) {
			serviceConfig.Apps = append(slices.Clone(serviceConfig.Apps), hostname)
		}
		if _, e = cluster.GenerateServices(serviceConfig); e != nil {
			return e
		}
		if err = m.Publish(ctx, hostname, parts[0], parts[1], port); err != nil {
			return err
		}
		err = srv.Update(ctx, func(s *coordinator.State) error {
			var services cluster.ServiceConfig
			if json.Unmarshal(s.Extensions[servicesExtension], &services) != nil {
				return errors.New("missing service configuration")
			}
			if !slices.Contains(services.Apps, hostname) {
				services.Apps = append(services.Apps, hostname)
			}
			if _, e := cluster.GenerateServices(services); e != nil {
				return e
			}
			i.Services = services
			return storeServices(s, services)
		})
		if err != nil {
			return err
		}
		if err = saveInstallation(*dir, i); err != nil {
			return err
		}
		return m.ApplyRegisteredServices(ctx)
	}
	return nil
}

func runRelayCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	var c relay.Config
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:3340", "loopback HTTP listener behind TLS gateway")
	fs.StringVar(&c.STUNListen, "stun-listen", ":3478", "STUN UDP listener")
	fs.StringVar(&c.VerifyURL, "verify-url", "", "coordinator HTTPS /verify endpoint")
	fs.StringVar(&c.StateDir, "state-dir", "", "private relay directory")
	fs.StringVar(&c.KeyFile, "key-file", "", "Kubernetes Secret key file")
	if e := parse(fs, args); e != nil {
		return e
	}
	return relay.Run(ctx, c)
}
