// Package enrollment coordinates authenticated, resumable network and K3s
// enrollment. Network membership is committed before any cluster token leaves
// the broker, and a reverse overlay probe is required before releasing it.
package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"tailscale.com/tailcfg"
)

const Extension = "cluster-enrollment-v1"
const ProbePort = 9444

type Cluster struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	HostCIDR      string `json:"hostCIDR"`
	PodCIDR       string `json:"podCIDR"`
	ServiceCIDR   string `json:"serviceCIDR"`
	DesiredVoters int    `json:"desiredVoters"`
	Image         string `json:"image"`
}
type Registry struct {
	Cluster      Cluster            `json:"cluster"`
	Invites      map[string]*Invite `json:"invites"`
	Members      map[string]*Member `json:"members"`
	PendingVoter string             `json:"pendingVoter,omitempty"`
	Cloud        *DesiredCloud      `json:"cloud,omitempty"`
}
type Invite struct {
	Name        string    `json:"name,omitempty"`
	Role        string    `json:"role"`
	Voter       bool      `json:"voter"`
	PublicIP    string    `json:"publicIP,omitempty"`
	RelayDomain string    `json:"relayDomain,omitempty"`
	Expires     time.Time `json:"expires"`
	Machine     string    `json:"machine,omitempty"`
}
type Member struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Voter     bool   `json:"voter"`
	PublicKey []byte `json:"publicKey"`
	Ready     bool   `json:"ready"`
}
type Invitation struct {
	Version     int       `json:"version"`
	ClusterID   string    `json:"clusterID"`
	URL         string    `json:"url"`
	Token       string    `json:"token"`
	Expires     time.Time `json:"expires"`
	Role        string    `json:"role"`
	Voter       bool      `json:"voter"`
	Name        string    `json:"name,omitempty"`
	PublicIP    string    `json:"publicIP,omitempty"`
	RelayDomain string    `json:"relayDomain,omitempty"`
}
type Request struct {
	ClusterID string           `json:"clusterID"`
	Action    string           `json:"action"`
	Node      coordinator.Node `json:"node"`
	PublicKey []byte           `json:"publicKey"`
	Issued    time.Time        `json:"issued"`
	Signature []byte           `json:"signature"`
}
type Grant struct {
	Cluster       Cluster                     `json:"cluster"`
	Role          string                      `json:"role"`
	Voter         bool                        `json:"voter"`
	Self          *tailcfg.Node               `json:"self"`
	Peers         []*tailcfg.Node             `json:"peers"`
	DERPMap       *tailcfg.DERPMap            `json:"derpMap,omitempty"`
	Policy        []tailcfg.FilterRule        `json:"policy"`
	HubEndpoints  map[string][]netip.AddrPort `json:"hubEndpoints"`
	ServerURLs    []string                    `json:"serverURLs"`
	Token         string                      `json:"token,omitempty"`
	Configuration *NodeConfiguration          `json:"configuration,omitempty"`
}

type Backend interface {
	// Healthy verifies the Kubernetes API, etcd readiness and each named voter.
	Healthy(context.Context, []string) error
	Token(context.Context, bool) (string, error)
	// ValidateNode rejects stale names before enrollment and verifies the expected
	// overlay address, hub/worker role and voter label before completing a join.
	ValidateNode(context.Context, coordinator.Node, bool, bool) error
	// PodRoutes returns the pod CIDRs assigned by Kubernetes to this node.
	PodRoutes(context.Context, string) ([]netip.Prefix, error)
	Probe(context.Context, netip.Addr, ed25519.PublicKey) error
}
type Broker struct {
	Store   coordinator.Store
	Update  func(context.Context, func(*coordinator.State) error) error
	Backend Backend
}

func ReadRegistry(s *coordinator.State) (Registry, error) {
	var r Registry
	if json.Unmarshal(s.Extensions[Extension], &r) != nil || r.Cluster.ID == "" || r.Invites == nil || r.Members == nil {
		return r, errors.New("cluster enrollment is not initialized")
	}
	return r, nil
}
func WriteRegistry(s *coordinator.State, r Registry) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if s.Extensions == nil {
		s.Extensions = map[string]json.RawMessage{}
	}
	s.Extensions[Extension] = b
	return nil
}
func (b *Broker) Invite(ctx context.Context, role string, voter bool, ttl time.Duration) (Invitation, error) {
	if (role != "hub" && role != "worker") || (voter && role != "hub") || ttl <= 0 || ttl > 24*time.Hour {
		return Invitation{}, errors.New("invalid invitation role or lifetime (maximum 24h)")
	}
	token, err := coordinator.NewToken()
	if err != nil {
		return Invitation{}, err
	}
	expiry := time.Now().UTC().Add(ttl)
	var result Invitation
	err = b.Update(ctx, func(s *coordinator.State) error {
		r, err := ReadRegistry(s)
		if err != nil {
			return err
		}
		if r.Cloud != nil {
			return errors.New("declarative clouds require an invitation for a declared node")
		}
		r.Invites[coordinator.TokenHash(token)] = &Invite{Role: role, Voter: voter, Expires: expiry}
		result = Invitation{Version: 1, ClusterID: r.Cluster.ID, URL: r.Cluster.URL, Token: token, Expires: expiry, Role: role, Voter: voter}
		return WriteRegistry(s, r)
	})
	return result, err
}

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func Sign(r Request, k ed25519.PrivateKey) Request {
	r.PublicKey = k.Public().(ed25519.PublicKey)
	r.Signature = nil
	data, _ := json.Marshal(r)
	r.Signature = ed25519.Sign(k, data)
	return r
}
func validRequest(r Request) bool {
	if len(r.PublicKey) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize || !namePattern.MatchString(r.Node.Hostname) || r.Node.MachineKey == "" || time.Since(r.Issued) > 5*time.Minute || time.Until(r.Issued) > time.Minute {
		return false
	}
	sig := r.Signature
	r.Signature = nil
	data, _ := json.Marshal(r)
	return ed25519.Verify(r.PublicKey, data, sig)
}

func (b *Broker) Handler() http.Handler {
	active := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			http.Error(w, "enrollment busy", 429)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		var req Request
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF || !validRequest(req) {
			http.Error(w, "invalid signed enrollment request", 400)
			return
		}
		if r.URL.Path != "/v1/"+req.Action || (req.Action != "enroll" && req.Action != "confirm" && req.Action != "complete" && req.Action != "config") {
			http.NotFound(w, r)
			return
		}
		var grant Grant
		var err error
		switch req.Action {
		case "enroll":
			grant, err = b.enroll(ctx, req, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		case "confirm":
			grant, err = b.confirm(ctx, req, false)
		case "complete":
			grant, err = b.confirm(ctx, req, true)
		case "config":
			grant, err = b.configuration(ctx, req)
		}
		if err != nil {
			http.Error(w, "enrollment denied or cluster unavailable; retain identity and retry", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(grant)
	})
}

func (b *Broker) enroll(ctx context.Context, req Request, token string) (Grant, error) {
	if len(token) != 68 {
		return Grant{}, coordinator.ErrUnauthorized
	}
	var result Grant
	err := b.Update(ctx, func(s *coordinator.State) error {
		r, err := ReadRegistry(s)
		if err != nil {
			return err
		}
		inv := r.Invites[coordinator.TokenHash(token)]
		if r.Cluster.ID != req.ClusterID || inv == nil {
			return coordinator.ErrUnauthorized
		}
		if inv.Machine != "" {
			if inv.Machine != req.Node.MachineKey || !sameMember(r.Members[inv.Machine], req) {
				return coordinator.ErrUnauthorized
			}
			_, result, err = authorized(s, req)
			return err
		}
		// Adopting a cloud closes all previously issued unbound capabilities.
		// A capability is never authority to claim a different declaration.
		if err := validateInviteNode(r, inv, req.Node); err != nil {
			return err
		}
		// Expiry limits who can claim an unused capability. Once claimed, the
		// persisted signing identity may recover a lost grant after expiration;
		// otherwise a response loss could permanently strand its address claim.
		if !time.Now().Before(inv.Expires) {
			return coordinator.ErrUnauthorized
		}
		for _, m := range r.Members {
			if m.Name == req.Node.Hostname {
				return errors.New("name reserved")
			}
		}
		voters := []string{}
		for _, m := range r.Members {
			if m.Voter {
				if !m.Ready {
					return errors.New("voter still joining")
				}
				voters = append(voters, m.Name)
			}
		}
		if inv.Voter && (r.PendingVoter != "" || len(voters) >= r.Cluster.DesiredVoters) {
			return errors.New("voter limit or pending join")
		}
		if err := b.Backend.Healthy(ctx, voters); err != nil {
			return err
		}
		n := coordinator.Node{MachineKey: req.Node.MachineKey, NodeKey: req.Node.NodeKey, DiscoKey: req.Node.DiscoKey, Hostname: req.Node.Hostname, Role: inv.Role, Endpoints: req.Node.Endpoints}
		n.Hostinfo = &tailcfg.Hostinfo{Hostname: n.Hostname, OS: "linux"}
		if len(n.Endpoints) > 16 {
			return errors.New("too many endpoints")
		}
		for _, ep := range n.Endpoints {
			if !ep.IsValid() || ep.Port() == 0 || ep.Addr().IsLoopback() || ep.Addr().IsMulticast() || ep.Addr().IsUnspecified() {
				return errors.New("invalid endpoint")
			}
		}
		if inv.Role == "hub" && len(n.Endpoints) == 0 {
			return errors.New("hubs require directly reachable endpoints")
		}
		if err := coordinator.AllocateNode(s, &n); err != nil {
			return err
		}
		if err := b.Backend.ValidateNode(ctx, n, inv.Voter, false); err != nil {
			return err
		}
		inv.Machine = n.MachineKey
		r.Members[n.MachineKey] = &Member{Name: n.Hostname, Role: inv.Role, Voter: inv.Voter, PublicKey: req.PublicKey}
		if inv.Voter {
			r.PendingVoter = n.MachineKey
		}
		if err := WriteRegistry(s, r); err != nil {
			return err
		}
		result, err = grantFor(s, r, n.MachineKey)
		return err
	})
	return result, err
}
func sameMember(m *Member, r Request) bool {
	return m != nil && m.Name == r.Node.Hostname && string(m.PublicKey) == string(r.PublicKey)
}

func grantFor(s *coordinator.State, r Registry, machine string) (Grant, error) {
	m := r.Members[machine]
	if m == nil {
		return Grant{}, coordinator.ErrUnauthorized
	}
	snapshot, err := coordinator.MapForState(s, machine)
	if err != nil {
		return Grant{}, err
	}
	var workloadRanges []netip.Prefix
	for _, raw := range []string{r.Cluster.PodCIDR, r.Cluster.ServiceCIDR} {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return Grant{}, errors.New("invalid cluster workload ranges")
		}
		workloadRanges = append(workloadRanges, prefix)
	}
	g := Grant{Cluster: r.Cluster, Role: m.Role, Voter: m.Voter, Self: snapshot.Node, Peers: snapshot.Peers, DERPMap: snapshot.DERPMap, Policy: snapshot.PacketFilter, HubEndpoints: map[string][]netip.AddrPort{}}
	if r.Cloud != nil {
		declared, ok := r.Cloud.Spec.Nodes[m.Name]
		if !ok || declared.Role != m.Role || declared.Voter != m.Voter {
			return Grant{}, errors.New("member differs from its cloud declaration")
		}
		declared.Connection = cloudconfig.Connection{}
		g.Configuration = &NodeConfiguration{Revision: r.Cloud.Revision, Name: m.Name, Node: declared}
	}
	for _, p := range append([]*tailcfg.Node{snapshot.Node}, snapshot.Peers...) {
		// Bootstrap has no local opt-in to Internet egress or arbitrary subnets.
		// Include only assigned host addresses and the cluster workload ranges;
		// subsequent native maps still carry every approved route for the host
		// agent to filter according to its independently saved local choices.
		unapproved := func(route netip.Prefix) bool {
			if slices.Contains(p.Addresses, route) {
				return false
			}
			for _, workload := range workloadRanges {
				if route.IsValid() && route.Bits() >= workload.Bits() && workload.Contains(route.Addr()) {
					return false
				}
			}
			return true
		}
		p.AllowedIPs = slices.DeleteFunc(p.AllowedIPs, unapproved)
		p.PrimaryRoutes = slices.DeleteFunc(p.PrimaryRoutes, unapproved)
		if !slices.Contains(p.Tags, "tag:hub") {
			continue
		}
		g.HubEndpoints[p.Key.String()] = p.Endpoints
		// An overlay-connected joining hub cannot yet serve the Kubernetes API.
		// Only durable completed hub members are join targets.
		hub := r.Members[p.Machine.String()]
		if hub != nil && hub.Ready && len(p.Addresses) > 0 {
			g.ServerURLs = append(g.ServerURLs, "https://"+p.Addresses[0].Addr().String()+":6443")
		}
	}
	return g, nil
}

// authorized revalidates the durable enrollment identity after slow external
// checks. A signed request alone is insufficient once a node has been revoked.
func authorized(s *coordinator.State, req Request) (Registry, Grant, error) {
	r, err := ReadRegistry(s)
	if err != nil {
		return r, Grant{}, err
	}
	n := s.Nodes[req.Node.MachineKey]
	if r.Cluster.ID != req.ClusterID || !sameMember(r.Members[req.Node.MachineKey], req) || n == nil || n.NodeKey != req.Node.NodeKey {
		return r, Grant{}, coordinator.ErrUnauthorized
	}
	g, err := grantFor(s, r, req.Node.MachineKey)
	return r, g, err
}
func (b *Broker) confirm(ctx context.Context, req Request, complete bool) (Grant, error) {
	s, err := b.Store.Load(ctx)
	if err != nil {
		return Grant{}, err
	}
	registry, g, err := authorized(s, req)
	if err != nil {
		return Grant{}, err
	}
	if complete {
		if err := b.Backend.ValidateNode(ctx, *s.Nodes[req.Node.MachineKey], registry.Members[req.Node.MachineKey].Voter, true); err != nil {
			return Grant{}, err
		}
		routes, err := b.Backend.PodRoutes(ctx, s.Nodes[req.Node.MachineKey].Hostname)
		if err != nil {
			return Grant{}, err
		}
		err = b.Update(ctx, func(current *coordinator.State) error {
			r, _, err := authorized(current, req)
			if err != nil {
				return err
			}
			m := r.Members[req.Node.MachineKey]
			if m.Voter && !m.Ready && r.PendingVoter != req.Node.MachineKey {
				return errors.New("voter join reservation changed")
			}
			if err := ApprovePodRoutes(current, req.Node.MachineKey, r.Cluster.PodCIDR, routes); err != nil {
				return err
			}
			m.Ready = true
			if r.PendingVoter == req.Node.MachineKey {
				r.PendingVoter = ""
			}
			if err = WriteRegistry(current, r); err != nil {
				return err
			}
			g, err = grantFor(current, r, req.Node.MachineKey)
			return err
		})
		return g, err
	}
	if err := b.Backend.Probe(ctx, g.Self.Addresses[0].Addr(), req.PublicKey); err != nil {
		return Grant{}, err
	}
	// The CAS is an authorization fence after probing: revocation or replacement
	// during the network check must not release a credential. Revocations after a
	// credential has been granted require Kubernetes credential revocation too.
	err = b.Update(ctx, func(current *coordinator.State) error {
		r, refreshed, err := authorized(current, req)
		if err != nil {
			return err
		}
		member := r.Members[req.Node.MachineKey]
		if member.Voter && !member.Ready && r.PendingVoter != req.Node.MachineKey {
			return errors.New("voter join reservation changed")
		}
		voters := []string{}
		for _, m := range r.Members {
			if m.Voter && m.Ready {
				voters = append(voters, m.Name)
			}
		}
		if err = b.Backend.Healthy(ctx, voters); err != nil {
			return err
		}
		g = refreshed
		return nil
	})
	if err != nil {
		return Grant{}, err
	}
	g.Token, err = b.Backend.Token(ctx, g.Role == "hub")
	return g, err
}

// ApprovePodRoutes records a trusted Kubernetes allocation. Callers must obtain
// routes from the API, never a joining host. The mutation belongs in the same
// state CAS as membership completion, after checking the durable identity again.
func ApprovePodRoutes(s *coordinator.State, machine, clusterPodCIDR string, routes []netip.Prefix) error {
	n := s.Nodes[machine]
	if n == nil || n.Revoked {
		return coordinator.ErrUnauthorized
	}
	pool, err := netip.ParsePrefix(clusterPodCIDR)
	if err != nil || !pool.Addr().Is4() || pool != pool.Masked() || len(routes) == 0 || len(routes) > 16 {
		return errors.New("invalid Kubernetes pod allocation")
	}
	for i, route := range routes {
		if !route.IsValid() || !route.Addr().Is4() || route != route.Masked() || route.Bits() < pool.Bits() || !pool.Contains(route.Addr()) {
			return errors.New("Kubernetes pod allocation is outside the cluster pod CIDR")
		}
		for _, other := range routes[:i] {
			if route.Overlaps(other) {
				return errors.New("overlapping Kubernetes pod allocations")
			}
		}
		for peerMachine, peer := range s.Nodes {
			if peerMachine == machine || peer.Revoked {
				continue
			}
			for _, allocated := range peer.PodRoutes {
				if route.Overlaps(allocated) {
					return errors.New("Kubernetes pod allocation belongs to another node")
				}
			}
		}
	}
	approvals := slices.DeleteFunc(slices.Clone(n.ApprovedRoutes), func(route netip.Prefix) bool {
		return slices.Contains(n.PodRoutes, route)
	})
	for _, route := range routes {
		if !slices.Contains(approvals, route) {
			approvals = append(approvals, route)
		}
	}
	n.ApprovedRoutes = approvals
	n.PodRoutes = slices.Clone(routes)
	return nil
}

// ProbeHandler proves that the enrolled device is reachable through its overlay
// address. Challenges contain no credentials and are signed with a local key.
func ProbeHandler(k ed25519.PrivateKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("challenge"))
		if r.Method != "GET" || r.URL.Path != "/probe" || err != nil || len(challenge) != 32 {
			http.Error(w, "invalid challenge", 400)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(ed25519.Sign(k, append([]byte("deepai-connect-overlay-probe-v1:"), challenge...)))
	})
}
func Probe(ctx context.Context, ip netip.Addr, pub ed25519.PublicKey) error {
	if !netip.MustParsePrefix(coordinator.DefaultNetwork).Contains(ip) {
		return errors.New("invalid overlay probe address")
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	u := fmt.Sprintf("http://%s:%d/probe?challenge=%s", ip, ProbePort, base64.RawURLEncoding.EncodeToString(challenge))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirect") }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("reverse overlay probe failed")
	}
	defer resp.Body.Close()
	sig, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil || resp.StatusCode != 200 || len(sig) != 64 || !ed25519.Verify(pub, append([]byte("deepai-connect-overlay-probe-v1:"), challenge...), sig) {
		return errors.New("reverse overlay identity mismatch")
	}
	return nil
}
