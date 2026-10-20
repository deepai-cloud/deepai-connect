// Package cloudconfig defines the declarative cloud manifest shared by the
// administrator, coordinator and joining nodes. It contains no device secrets
// or runtime identities.
package cloudconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "connect.deepai.cloud/v1alpha1"
	Kind       = "Cloud"

	// MaxManifestSize bounds YAML parsing both from disk and over the API.
	MaxManifestSize = 1 << 20
)

type Cloud struct {
	APIVersion string          `json:"apiVersion" yaml:"apiVersion"`
	Kind       string          `json:"kind" yaml:"kind"`
	Name       string          `json:"name" yaml:"name"`
	Network    Network         `json:"network" yaml:"network"`
	Nodes      map[string]Node `json:"nodes" yaml:"nodes"`
	Bootstrap  Bootstrap       `json:"bootstrap" yaml:"bootstrap"`
}

type Network struct {
	Domain           string `json:"domain" yaml:"domain"`
	HostCIDR         string `json:"hostCIDR" yaml:"hostCIDR"`
	PodCIDR          string `json:"podCIDR" yaml:"podCIDR"`
	ServiceCIDR      string `json:"serviceCIDR" yaml:"serviceCIDR"`
	PacketPolicyFile string `json:"packetPolicyFile,omitempty" yaml:"packetPolicyFile,omitempty"`
}

type Node struct {
	Role        string            `json:"role" yaml:"role"`
	Voter       bool              `json:"voter" yaml:"voter"`
	PublicIP    string            `json:"publicIP,omitempty" yaml:"publicIP,omitempty"`
	RelayDomain string            `json:"relayDomain,omitempty" yaml:"relayDomain,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Connection  Connection        `json:"connection,omitempty" yaml:"connection,omitempty"`
}

type Connection struct {
	// SSH is optional administrative access to a hub. Nodes authenticate to the
	// coordinator with their own persistent identity after invitation enrollment.
	SSH string `json:"ssh,omitempty" yaml:"ssh,omitempty"`
}

type Bootstrap struct {
	Node        string `json:"node" yaml:"node"`
	Image       string `json:"image" yaml:"image"`
	Voters      int    `json:"voters" yaml:"voters"`
	TLSCertFile string `json:"tlsCertFile,omitempty" yaml:"tlsCertFile,omitempty"`
	TLSKeyFile  string `json:"tlsKeyFile,omitempty" yaml:"tlsKeyFile,omitempty"`
}

// Load reads one bounded manifest. File references remain relative to the
// manifest; the caller resolves them when loading local bootstrap material.
func Load(path string) (*Cloud, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cloud manifest: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("read cloud manifest: %w", err)
	}
	return Parse(data)
}

// Parse accepts one strict YAML document, applies defaults, then validates it.
// An explicitly disabled bootstrap voter is rejected rather than overwritten.
func Parse(data []byte) (*Cloud, error) {
	if len(data) > MaxManifestSize {
		return nil, fmt.Errorf("cloud manifest exceeds %d bytes", MaxManifestSize)
	}
	var doc yaml.Node
	treeDecoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := treeDecoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode cloud manifest: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("cloud manifest must be a YAML mapping")
	}
	var extra yaml.Node
	if err := treeDecoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("decode cloud manifest: %w", err)
		}
		return nil, errors.New("cloud manifest must contain exactly one YAML document")
	}
	if err := validateYAML(&doc); err != nil {
		return nil, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var c Cloud
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode cloud manifest: %w", err)
	}
	if c.Network.HostCIDR == "" {
		c.Network.HostCIDR = "100.64.0.0/10"
	}
	if c.Network.PodCIDR == "" {
		c.Network.PodCIDR = "10.42.0.0/16"
	}
	if c.Network.ServiceCIDR == "" {
		c.Network.ServiceCIDR = "10.43.0.0/16"
	}
	if c.Bootstrap.Voters == 0 {
		c.Bootstrap.Voters = 3
	}
	if node, ok := c.Nodes[c.Bootstrap.Node]; ok && mappingValue(mappingValue(mappingValue(doc.Content[0], "nodes"), c.Bootstrap.Node), "voter") == nil {
		node.Voter = true
		c.Nodes[c.Bootstrap.Node] = node
	}
	if err := Validate(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// validateYAML prevents aliases, merge keys and duplicate keys from obscuring
// the definition being reviewed. yaml's KnownFields handles the schema itself.
func validateYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("cloud manifest does not support YAML anchors or aliases")
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("cloud manifest line %d: mapping keys must be strings", key.Line)
			}
			if seen[key.Value] {
				return fmt.Errorf("cloud manifest line %d: duplicate key %q", key.Line, key.Value)
			}
			seen[key.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := validateYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

var (
	dnsLabel      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	labelPart     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)
	sshUser       = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$`)
	imagePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostPool      = netip.MustParsePrefix("100.64.0.0/10")
)

// Validate checks a manifest that already has its defaults. It does not mutate
// the manifest, read referenced files, or contact any node.
func Validate(c *Cloud) error {
	if c == nil {
		return errors.New("cloud manifest is required")
	}
	if c.APIVersion != APIVersion || c.Kind != Kind {
		return fmt.Errorf("cloud manifest requires apiVersion %q and kind %q", APIVersion, Kind)
	}
	if !dnsLabel.MatchString(c.Name) {
		return errors.New("cloud name must be a lowercase DNS label")
	}
	if !validDomain(c.Network.Domain, true) {
		return errors.New("network.domain must be a lowercase DNS hostname")
	}
	ranges := []struct{ name, value string }{
		{"hostCIDR", c.Network.HostCIDR},
		{"podCIDR", c.Network.PodCIDR},
		{"serviceCIDR", c.Network.ServiceCIDR},
	}
	var prior []netip.Prefix
	for index, value := range ranges {
		p, err := netip.ParsePrefix(value.value)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() > 24 {
			return fmt.Errorf("network.%s must be a canonical IPv4 network of /24 or larger", value.name)
		}
		if index == 0 && (p.Bits() < hostPool.Bits() || !hostPool.Contains(p.Addr())) {
			return errors.New("network.hostCIDR must be within 100.64.0.0/10")
		}
		for i, other := range prior {
			if p.Overlaps(other) {
				return fmt.Errorf("network.%s overlaps network.%s", value.name, ranges[i].name)
			}
		}
		prior = append(prior, p)
	}
	if c.Bootstrap.Voters != 3 && c.Bootstrap.Voters != 5 {
		return errors.New("bootstrap.voters must be three or five; the initial hub bootstraps alone")
	}
	if !pinnedImage(c.Bootstrap.Image) {
		return errors.New("bootstrap.image requires an explicit release tag or sha256 digest")
	}
	if (c.Bootstrap.TLSCertFile == "") != (c.Bootstrap.TLSKeyFile == "") {
		return errors.New("bootstrap.tlsCertFile and bootstrap.tlsKeyFile must be provided together")
	}
	for _, ref := range []struct{ name, value string }{
		{"network.packetPolicyFile", c.Network.PacketPolicyFile},
		{"bootstrap.tlsCertFile", c.Bootstrap.TLSCertFile},
		{"bootstrap.tlsKeyFile", c.Bootstrap.TLSKeyFile},
	} {
		if strings.ContainsAny(ref.value, "\r\n\x00") {
			return fmt.Errorf("%s contains an invalid path character", ref.name)
		}
	}
	initial, exists := c.Nodes[c.Bootstrap.Node]
	if !exists || initial.Role != "hub" || !initial.Voter {
		return errors.New("bootstrap.node must name a declared hub with voter enabled")
	}
	names := make([]string, 0, len(c.Nodes))
	for name := range c.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	relays := make(map[string]string)
	voters := 0
	for _, name := range names {
		n := c.Nodes[name]
		if err := ValidateNode(name, n); err != nil {
			return err
		}
		if n.Role == "hub" {
			if other, exists := relays[n.RelayDomain]; exists {
				return fmt.Errorf("nodes %s and %s must have unique relayDomain hostnames", other, name)
			}
			relays[n.RelayDomain] = name
			if n.Voter {
				voters++
			}
		}
	}
	if voters > c.Bootstrap.Voters {
		return errors.New("declared voting hubs exceed bootstrap.voters")
	}
	return nil
}

// ValidateNode checks one declared node independently of cloud-wide uniqueness
// and bootstrap requirements. It also validates configuration received by a
// joining node before it can be persisted or applied.
func ValidateNode(name string, n Node) error {
	if !dnsLabel.MatchString(name) {
		return fmt.Errorf("node %q must have a lowercase DNS label name", name)
	}
	if err := ValidateLabels(n.Labels); err != nil {
		return fmt.Errorf("node %s: %w", name, err)
	}
	switch n.Role {
	case "hub":
		public, err := netip.ParseAddr(n.PublicIP)
		if err != nil || !public.Is4() || !public.IsGlobalUnicast() || public.IsPrivate() || hostPool.Contains(public) {
			return fmt.Errorf("node %s: hubs require a directly reachable public IPv4 address", name)
		}
		if !validDomain(n.RelayDomain, true) {
			return fmt.Errorf("node %s: relayDomain must be a lowercase DNS hostname", name)
		}
		if n.Connection.SSH != "" {
			if err := ValidateSSH(n.Connection.SSH); err != nil {
				return fmt.Errorf("node %s: %w", name, err)
			}
		}
	case "worker":
		if n.Voter || n.PublicIP != "" || n.RelayDomain != "" || n.Connection.SSH != "" {
			return fmt.Errorf("node %s: workers cannot set voter, publicIP, relayDomain or connection.ssh; workers join with invitations", name)
		}
	default:
		return fmt.Errorf("node %s: role must be hub or worker", name)
	}
	return nil
}

// ValidateLabels accepts Kubernetes labels except reserved namespaces that can
// confer platform roles or impersonate labels maintained by Connect itself.
func ValidateLabels(labels map[string]string) error {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts := strings.Split(key, "/")
		if len(parts) > 2 || !labelPart.MatchString(parts[len(parts)-1]) {
			return fmt.Errorf("invalid label key %q", key)
		}
		if len(parts) == 2 {
			prefix := parts[0]
			if !validDomain(prefix, false) {
				return fmt.Errorf("invalid label prefix %q", prefix)
			}
			for _, reserved := range []string{"kubernetes.io", "k8s.io", "connect.deepai.cloud"} {
				if prefix == reserved || strings.HasSuffix(prefix, "."+reserved) {
					return fmt.Errorf("label key %q uses reserved prefix %s", key, reserved)
				}
			}
		}
		if value := labels[key]; value != "" && !labelPart.MatchString(value) {
			return fmt.Errorf("invalid value for label %q", key)
		}
	}
	return nil
}

func validDomain(name string, requireDot bool) bool {
	if len(name) == 0 || len(name) > 253 || (requireDot && !strings.Contains(name, ".")) {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if !dnsLabel.MatchString(part) {
			return false
		}
	}
	return true
}

// ValidateSSH accepts an OpenSSH destination, not a command or an argument list.
// Remote execution must still pass this as one argument and quote its command.
func ValidateSSH(destination string) error {
	if !validSSH(destination) {
		return errors.New("connection.ssh must be user@host without options, ports or commands")
	}
	return nil
}

func validSSH(destination string) bool {
	if strings.Count(destination, "@") != 1 {
		return false
	}
	user, host, _ := strings.Cut(destination, "@")
	if !sshUser.MatchString(user) {
		return false
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ip, err := netip.ParseAddr(host[1 : len(host)-1])
		return err == nil && ip.Is6() && ip.Zone() == ""
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Is4()
	}
	return validDomain(host, false)
}

func pinnedImage(image string) bool {
	if !imagePattern.MatchString(image) {
		return false
	}
	if strings.Contains(image, "@") {
		parts := strings.Split(image, "@sha256:")
		return len(parts) == 2 && parts[0] != "" && !strings.Contains(parts[0], "@") && digestPattern.MatchString(parts[1])
	}
	last := image[strings.LastIndex(image, "/")+1:]
	at := strings.LastIndex(last, ":")
	if at <= 0 || at == len(last)-1 {
		return false
	}
	switch strings.ToLower(last[at+1:]) {
	case "latest", "main", "dev":
		return false
	}
	return true
}
