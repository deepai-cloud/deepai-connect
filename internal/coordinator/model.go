// Package coordinator implements the Tailscale control protocol using Kubernetes
// as its durable, compare-and-swap state store. No device private keys are stored.
package coordinator

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	ErrConflict     = errors.New("resource version conflict")
	ErrUnauthorized = errors.New("not authorized")
	ErrNotFound     = errors.New("not found")
)

const DefaultNetwork = "100.64.0.0/10"

// State is one Kubernetes resource so claims, address allocation and policy
// changes have a single atomic commit point even with multiple coordinators.
type State struct {
	Revision    string                     `json:"-"`
	NextID      uint64                     `json:"nextID"`
	Network     string                     `json:"network"`
	Domain      string                     `json:"domain"`
	Nodes       map[string]*Node           `json:"nodes"`
	Invitations map[string]*Invitation     `json:"invitations"`
	Policy      []tailcfg.FilterRule       `json:"policy"`
	DERPMap     *tailcfg.DERPMap           `json:"derpMap,omitempty"`
	Extensions  map[string]json.RawMessage `json:"extensions,omitempty"`
}

type Node struct {
	ID             uint64           `json:"id"`
	MachineKey     string           `json:"machineKey"`
	NodeKey        string           `json:"nodeKey"`
	DiscoKey       string           `json:"discoKey,omitempty"`
	Hostname       string           `json:"hostname"`
	Role           string           `json:"role"`
	Addresses      []netip.Prefix   `json:"addresses"`
	Endpoints      []netip.AddrPort `json:"endpoints,omitempty"`
	ApprovedRoutes []netip.Prefix   `json:"approvedRoutes,omitempty"`
	// PodRoutes records the Kubernetes-assigned routes so reconciliation replaces
	// only those approvals and preserves independent gateway route approvals.
	PodRoutes []netip.Prefix            `json:"podRoutes,omitempty"`
	Hostinfo  *tailcfg.Hostinfo         `json:"hostinfo,omitempty"`
	Cap       tailcfg.CapabilityVersion `json:"cap,omitempty"`
	Created   time.Time                 `json:"created"`
	LastSeen  time.Time                 `json:"lastSeen"`
	KeyExpiry time.Time                 `json:"keyExpiry,omitempty"`
	Revoked   bool                      `json:"revoked,omitempty"`
}

// Invitation secrets are returned once; only their SHA-256 digest is persisted.
// A zero UsesRemaining denotes an exhausted invitation, not unlimited reuse.
type Invitation struct {
	Role          string    `json:"role"`
	Expires       time.Time `json:"expires"`
	UsesRemaining int       `json:"usesRemaining"`
	Created       time.Time `json:"created"`
}

type Credentials struct{ NoisePrivate key.MachinePrivate }

type Store interface {
	Load(context.Context) (*State, error)
	CompareAndSwap(context.Context, *State, string) error
	LoadOrCreateCredentials(context.Context) (Credentials, error)
}

func NewState() *State {
	// Private host communication is enabled by default. Workload and Internet
	// routes need explicit approval; operators may replace this packet policy.
	return &State{NextID: 1, Network: DefaultNetwork, Domain: "connect.internal", Nodes: map[string]*Node{}, Invitations: map[string]*Invitation{}, Extensions: map[string]json.RawMessage{}, Policy: []tailcfg.FilterRule{{SrcIPs: []string{DefaultNetwork}, DstPorts: []tailcfg.NetPortRange{{IP: DefaultNetwork, Ports: tailcfg.PortRange{First: 0, Last: 65535}}}}}}
}

func (s *State) normalize() {
	if s.Nodes == nil {
		s.Nodes = map[string]*Node{}
	}
	if s.Invitations == nil {
		s.Invitations = map[string]*Invitation{}
	}
	if s.Extensions == nil {
		s.Extensions = map[string]json.RawMessage{}
	}
	if s.Network == "" {
		s.Network = DefaultNetwork
	}
	if s.Domain == "" {
		s.Domain = "connect.internal"
	}
	if s.NextID == 0 {
		s.NextID = 1
	}
}

func TokenHash(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}
func NewToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "dai-" + hex.EncodeToString(b[:]), nil
}

// AllocateNode validates public identities and allocates a never-reused node ID
// and unique host address. Call it inside Server.Update for atomic enrollment.
func AllocateNode(state *State, n *Node) error {
	state.normalize()
	var m key.MachinePublic
	var k key.NodePublic
	var d key.DiscoPublic
	if err := m.UnmarshalText([]byte(n.MachineKey)); err != nil || m.IsZero() {
		return errors.New("invalid machine public key")
	}
	if err := k.UnmarshalText([]byte(n.NodeKey)); err != nil || k.IsZero() {
		return errors.New("invalid node public key")
	}
	if n.MachineKey != m.String() || n.NodeKey != k.String() {
		return errors.New("public keys must use canonical text encoding")
	}
	if n.DiscoKey != "" {
		if err := d.UnmarshalText([]byte(n.DiscoKey)); err != nil || d.IsZero() {
			return errors.New("invalid discovery public key")
		}
	}
	if n.Role != "hub" && n.Role != "worker" && n.Role != "client" {
		return errors.New("role must be hub, worker, or client")
	}
	if existing := state.Nodes[n.MachineKey]; existing != nil {
		return errors.New("machine already enrolled")
	}
	for _, existing := range state.Nodes {
		if existing.NodeKey == n.NodeKey {
			return errors.New("node key already enrolled")
		}
	}
	netw, err := netip.ParsePrefix(state.Network)
	if err != nil || !netw.Addr().Is4() || netw != netw.Masked() || netw.Bits() < 10 || netw.Bits() > 30 || !netip.MustParsePrefix(DefaultNetwork).Contains(netw.Addr()) {
		return errors.New("host pool must be a network within 100.64.0.0/10")
	}
	used := map[netip.Addr]bool{}
	usedIDs := map[uint64]bool{}
	for _, existing := range state.Nodes {
		usedIDs[existing.ID] = true
		for _, p := range existing.Addresses {
			used[p.Addr()] = true
		}
	}
	if len(n.Addresses) == 0 {
		for ip := netw.Addr().Next(); netw.Contains(ip); ip = ip.Next() {
			if !used[ip] {
				n.Addresses = []netip.Prefix{netip.PrefixFrom(ip, 32)}
				break
			}
		}
		if len(n.Addresses) == 0 {
			return errors.New("host address pool exhausted")
		}
	}
	for _, p := range n.Addresses {
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() != 32 || !netw.Contains(p.Addr()) || p.Addr() == netw.Addr() || used[p.Addr()] {
			return errors.New("invalid or duplicate host address")
		}
		used[p.Addr()] = true
	}
	if n.ID == 0 {
		for usedIDs[state.NextID] {
			state.NextID++
		}
		n.ID = state.NextID
	}
	if n.ID >= 1<<63 || state.NextID >= 1<<63 {
		return errors.New("node ID space exhausted")
	}
	if usedIDs[n.ID] {
		return errors.New("duplicate node ID")
	}
	if n.ID >= state.NextID {
		state.NextID = n.ID + 1
	}
	if n.Hostname == "" {
		n.Hostname = fmt.Sprintf("host-%d", n.ID)
	}
	n.Hostname = safeHostname(n.Hostname)
	if n.Created.IsZero() {
		n.Created = time.Now().UTC()
	}
	if n.LastSeen.IsZero() {
		n.LastSeen = n.Created
	}
	copy := *n
	state.Nodes[n.MachineKey] = &copy
	return nil
}

func safeHostname(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	s = strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	if s == "" {
		return "host"
	}
	return s
}

func (n *Node) TailNode() *tailcfg.Node {
	return n.tailNode(time.Now(), "connect.internal")
}

func (n *Node) tailNode(now time.Time, domain string) *tailcfg.Node {
	var m key.MachinePublic
	_ = m.UnmarshalText([]byte(n.MachineKey))
	var k key.NodePublic
	_ = k.UnmarshalText([]byte(n.NodeKey))
	var d key.DiscoPublic
	_ = d.UnmarshalText([]byte(n.DiscoKey))
	online := !n.Revoked && now.Sub(n.LastSeen) < 90*time.Second
	t := &tailcfg.Node{ID: tailcfg.NodeID(n.ID), StableID: tailcfg.StableNodeID("connect-" + strconv.FormatUint(n.ID, 10)), Name: nodeName(n, domain), User: 1, Machine: m, Key: k, DiscoKey: d, Addresses: append([]netip.Prefix{}, n.Addresses...), AllowedIPs: append([]netip.Prefix{}, n.Addresses...), Endpoints: append([]netip.AddrPort{}, n.Endpoints...), Created: n.Created, LastSeen: &n.LastSeen, Online: &online, KeyExpiry: n.KeyExpiry, MachineAuthorized: !n.Revoked, Cap: n.Cap}
	if n.Role == "hub" {
		t.Tags = []string{"tag:hub"}
	}
	if n.Hostinfo != nil {
		t.Hostinfo = n.Hostinfo.View()
		if n.Hostinfo.NetInfo != nil {
			t.HomeDERP = n.Hostinfo.NetInfo.PreferredDERP
		}
	} else {
		t.Hostinfo = (&tailcfg.Hostinfo{Hostname: n.Hostname}).View()
	}
	return t
}

func nodeName(n *Node, domain string) string {
	suffix := "-" + strconv.FormatUint(n.ID, 10)
	host := n.Hostname
	if len(host)+len(suffix) > 63 {
		host = host[:63-len(suffix)]
	}
	return host + suffix + "." + strings.Trim(domain, ".") + "."
}

func active(n *Node, now time.Time) bool {
	return !n.Revoked && (n.KeyExpiry.IsZero() || now.Before(n.KeyExpiry))
}

func orderedNodes(s *State) []*Node {
	ns := make([]*Node, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		ns = append(ns, n)
	}
	slices.SortFunc(ns, func(a, b *Node) int { return cmp.Compare(a.ID, b.ID) })
	return ns
}
