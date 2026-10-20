package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// DesiredCloud is committed with membership and packet policy in the same
// coordinator CAS. The revision hashes the complete specification and effective
// policy, so repeated applies do not manufacture a configuration change.
type DesiredCloud struct {
	Revision string               `json:"revision"`
	Spec     cloudconfig.Cloud    `json:"spec"`
	Policy   []tailcfg.FilterRule `json:"policy"`
}

// NodeConfiguration is the authenticated member's own desired configuration.
// SSH administration details are deliberately excluded from grants.
type NodeConfiguration struct {
	Revision string           `json:"revision"`
	Name     string           `json:"name"`
	Node     cloudconfig.Node `json:"node"`
}

// ApplyCloud must run inside the coordinator's Update callback. It never
// reallocates addresses, replaces identities, revokes members, or changes
// installation parameters that need an explicit migration. A nil policy keeps
// the effective current policy; an empty, non-nil policy explicitly denies all.
func ApplyCloud(s *coordinator.State, spec *cloudconfig.Cloud, policy []tailcfg.FilterRule) (string, error) {
	replacePolicy := policy != nil
	if s == nil || spec == nil {
		return "", errors.New("cloud and coordinator state are required")
	}
	if err := cloudconfig.Validate(spec); err != nil {
		return "", err
	}
	r, err := ReadRegistry(s)
	if err != nil {
		return "", err
	}
	c := r.Cluster
	if c.URL != "https://"+spec.Network.Domain || c.HostCIDR != spec.Network.HostCIDR ||
		c.PodCIDR != spec.Network.PodCIDR || c.ServiceCIDR != spec.Network.ServiceCIDR ||
		c.Image != spec.Bootstrap.Image || c.DesiredVoters != spec.Bootstrap.Voters ||
		s.Network != spec.Network.HostCIDR {
		return "", errors.New("cloud network, domain, image or voter count differs from the installed cluster; explicit migration is required")
	}
	if r.Cloud != nil && (r.Cloud.Spec.Name != spec.Name || r.Cloud.Spec.Bootstrap.Node != spec.Bootstrap.Node) {
		return "", errors.New("cloud name and bootstrap node cannot change")
	}
	for machine, member := range r.Members {
		if member == nil {
			return "", errors.New("invalid enrollment member")
		}
		n, exists := spec.Nodes[member.Name]
		if !exists || n.Role != member.Role || n.Voter != member.Voter {
			return "", fmt.Errorf("enrolled node %q cannot be removed or change role/voter membership", member.Name)
		}
		actual := s.Nodes[machine]
		if actual == nil || actual.Hostname != member.Name || actual.Role != member.Role {
			return "", fmt.Errorf("enrolled node %q has inconsistent network membership", member.Name)
		}
		if r.Cloud != nil {
			old, exists := r.Cloud.Spec.Nodes[member.Name]
			if !exists || old.PublicIP != n.PublicIP || old.RelayDomain != n.RelayDomain {
				return "", fmt.Errorf("enrolled node %q requires an explicit hub endpoint migration", member.Name)
			}
		}
		if n.Role == "hub" {
			if err := validateHubEndpoints(s, actual, n); err != nil {
				return "", err
			}
		}
	}
	if policy == nil {
		policy = s.Policy
	}
	if policy == nil {
		policy = []tailcfg.FilterRule{}
	}
	if _, err := filter.MatchesFromFilterRules(policy); err != nil {
		return "", fmt.Errorf("invalid cloud packet policy: %w", err)
	}
	// Round-tripping detaches maps and slices from caller-owned input before
	// hashing and persisting; later input mutations cannot change committed state.
	raw, err := json.Marshal(DesiredCloud{Spec: *spec, Policy: policy})
	if err != nil {
		return "", err
	}
	var desired DesiredCloud
	if err := json.Unmarshal(raw, &desired); err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	desired.Revision = hex.EncodeToString(digest[:])
	r.Cloud = &desired
	if err := WriteRegistry(s, r); err != nil {
		return "", err
	}
	if replacePolicy {
		s.Policy = desired.Policy
	}
	return desired.Revision, nil
}

func validateHubEndpoints(s *coordinator.State, actual *coordinator.Node, declared cloudconfig.Node) error {
	if s.DERPMap != nil {
		for _, region := range s.DERPMap.Regions {
			if region == nil {
				continue
			}
			for _, relay := range region.Nodes {
				if relay != nil && relay.Name == actual.Hostname {
					if relay.HostName != declared.RelayDomain || relay.IPv4 != declared.PublicIP {
						return fmt.Errorf("registered hub %q endpoints differ from cloud declaration", actual.Hostname)
					}
					return nil
				}
			}
		}
	}
	for _, ep := range actual.Endpoints {
		if ep.IsValid() && ep.Addr().String() == declared.PublicIP {
			return nil
		}
	}
	return fmt.Errorf("hub %q does not advertise the declared public IP", actual.Hostname)
}

// InviteNode binds the single-use enrollment capability to one declared node.
// Reissuing an invitation never replaces a member that already owns the name.
func (b *Broker) InviteNode(ctx context.Context, name string, ttl time.Duration) (Invitation, error) {
	if !namePattern.MatchString(name) || ttl <= 0 || ttl > 24*time.Hour {
		return Invitation{}, errors.New("invalid node name or invitation lifetime (maximum 24h)")
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
		if r.Cloud == nil {
			return errors.New("apply a cloud before inviting a declared node")
		}
		n, exists := r.Cloud.Spec.Nodes[name]
		if !exists {
			return fmt.Errorf("node %q is not declared in the cloud", name)
		}
		for _, member := range r.Members {
			if member != nil && member.Name == name {
				return fmt.Errorf("node %q is already enrolled; resume its saved identity", name)
			}
		}
		r.Invites[coordinator.TokenHash(token)] = &Invite{Name: name, Role: n.Role, Voter: n.Voter, PublicIP: n.PublicIP, RelayDomain: n.RelayDomain, Expires: expiry}
		result = Invitation{Version: 1, ClusterID: r.Cluster.ID, URL: r.Cluster.URL, Token: token, Expires: expiry, Name: name, Role: n.Role, Voter: n.Voter, PublicIP: n.PublicIP, RelayDomain: n.RelayDomain}
		return WriteRegistry(s, r)
	})
	return result, err
}

func validateInviteNode(r Registry, inv *Invite, node coordinator.Node) error {
	if r.Cloud == nil {
		if inv.Name != "" {
			return coordinator.ErrUnauthorized
		}
		return nil
	}
	n, exists := r.Cloud.Spec.Nodes[inv.Name]
	if !exists || inv.Name != node.Hostname || n.Role != inv.Role || n.Voter != inv.Voter || n.PublicIP != inv.PublicIP || n.RelayDomain != inv.RelayDomain {
		return coordinator.ErrUnauthorized
	}
	if n.Role == "hub" {
		ip, err := netip.ParseAddr(n.PublicIP)
		if err != nil {
			return coordinator.ErrUnauthorized
		}
		found := false
		for _, ep := range node.Endpoints {
			if ep.IsValid() && ep.Addr() == ip && ep.Port() != 0 {
				found = true
			}
		}
		if !found {
			return errors.New("hub must advertise its declared public IP")
		}
	}
	return nil
}

func (b *Broker) configuration(ctx context.Context, req Request) (Grant, error) {
	s, err := b.Store.Load(ctx)
	if err != nil {
		return Grant{}, err
	}
	_, g, err := authorized(s, req)
	return g, err
}
