package cloudconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const validManifest = `apiVersion: connect.deepai.cloud/v1alpha1
kind: Cloud
name: personal-cloud
network:
  domain: mesh.example.com
  packetPolicyFile: network/policy.json
bootstrap:
  node: hub-1
  image: ghcr.io/deepai-cloud/connect:v1.2.3
  tlsCertFile: certs/gateway.crt
  tlsKeyFile: certs/gateway.key
nodes:
  hub-1:
    role: hub
    publicIP: 203.0.113.10
    relayDomain: relay-1.example.com
    connection:
      ssh: root@203.0.113.10
  mac-worker-1:
    role: worker
    labels:
      location: home
      example.com/pool: personal
`

func readValid(t *testing.T) *Cloud {
	t.Helper()
	c, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseDefaultsAndRoundTrips(t *testing.T) {
	c := readValid(t)
	if c.Network.HostCIDR != "100.64.0.0/10" || c.Network.PodCIDR != "10.42.0.0/16" || c.Network.ServiceCIDR != "10.43.0.0/16" {
		t.Fatalf("unexpected network defaults: %+v", c.Network)
	}
	if c.Bootstrap.Voters != 3 || !c.Nodes["hub-1"].Voter || c.Nodes["mac-worker-1"].Voter {
		t.Fatalf("unexpected voter defaults: %+v", c)
	}
	if c.Nodes["mac-worker-1"].Connection.SSH != "" {
		t.Fatal("worker unexpectedly needs SSH")
	}
	for _, marshal := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal} {
		data, err := marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c, roundTrip) {
			t.Fatalf("round-trip changed manifest:\n%s", data)
		}
	}
}

func TestLoadPreservesPortableFileReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.yaml")
	if err := os.WriteFile(path, []byte(validManifest), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Network.PacketPolicyFile != "network/policy.json" || c.Bootstrap.TLSCertFile != "certs/gateway.crt" || c.Bootstrap.TLSKeyFile != "certs/gateway.key" {
		t.Fatal("Load rewrote portable references or unexpectedly read bootstrap files")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", MaxManifestSize+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized disk manifest accepted: %v", err)
	}
}

func TestParseRejectsAmbiguousAndUnknownYAML(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "decode"},
		{"null", "null\n", "mapping"},
		{"list", "- name: cloud\n", "mapping"},
		{"malformed", "nodes: [", "decode"},
		{"second document", validManifest + "\n---\n" + validManifest, "exactly one"},
		{"trailing empty document", validManifest + "\n---\n", "exactly one"},
		{"unknown root", validManifest + "\nnetwrok: {}\n", "field netwrok"},
		{"unknown nested", strings.Replace(validManifest, "  domain:", "  typo: example\n  domain:", 1), "field typo"},
		{"unknown node", strings.Replace(validManifest, "    role: worker", "    cpus: 4\n    role: worker", 1), "field cpus"},
		{"duplicate root", validManifest + "\nname: another\n", "duplicate key"},
		{"duplicate node", validManifest + "  hub-1:\n    role: worker\n", "duplicate key"},
		{"duplicate label", validManifest + "      location: office\n", "duplicate key"},
		{"alias", strings.Replace(validManifest, "labels:\n", "labels: &labels\n", 1), "anchors or aliases"},
		{"numeric key", strings.Replace(validManifest, "  mac-worker-1:", "  123:", 1), "keys must be strings"},
		{"oversized", strings.Repeat(" ", MaxManifestSize+1), "exceeds"},
		{"explicit nonvoter bootstrap", strings.Replace(validManifest, "    role: hub", "    role: hub\n    voter: false", 1), "voter enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.data)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsInvalidClouds(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Cloud)
		want string
	}{
		{"wrong API", func(c *Cloud) { c.APIVersion = "v1" }, "apiVersion"},
		{"wrong kind", func(c *Cloud) { c.Kind = "Cluster" }, "kind"},
		{"invalid name", func(c *Cloud) { c.Name = "My Cloud" }, "cloud name"},
		{"uppercase domain", func(c *Cloud) { c.Network.Domain = "Mesh.example.com" }, "network.domain"},
		{"IP domain", func(c *Cloud) { c.Network.Domain = "203.0.113.10" }, "network.domain"},
		{"outside host pool", func(c *Cloud) { c.Network.HostCIDR = "10.10.0.0/16" }, "within"},
		{"uncanonical host", func(c *Cloud) { c.Network.HostCIDR = "100.64.0.1/16" }, "canonical"},
		{"small host pool", func(c *Cloud) { c.Network.HostCIDR = "100.64.0.0/25" }, "canonical"},
		{"IPv6 pod pool", func(c *Cloud) { c.Network.PodCIDR = "fd00::/64" }, "IPv4"},
		{"overlapping pools", func(c *Cloud) { c.Network.ServiceCIDR = c.Network.PodCIDR }, "overlaps"},
		{"invalid voters", func(c *Cloud) { c.Bootstrap.Voters = 1 }, "three or five"},
		{"missing image", func(c *Cloud) { c.Bootstrap.Image = "" }, "release tag"},
		{"latest image", func(c *Cloud) { c.Bootstrap.Image = "example/connect:latest" }, "release tag"},
		{"untagged image", func(c *Cloud) { c.Bootstrap.Image = "example/connect" }, "release tag"},
		{"wrong digest", func(c *Cloud) { c.Bootstrap.Image = "example/connect@sha256:bad" }, "release tag"},
		{"missing TLS key", func(c *Cloud) { c.Bootstrap.TLSKeyFile = "" }, "provided together"},
		{"invalid policy path", func(c *Cloud) { c.Network.PacketPolicyFile = "policy\nfile" }, "path character"},
		{"missing bootstrap node", func(c *Cloud) { c.Bootstrap.Node = "absent" }, "declared hub"},
		{"worker bootstrap", func(c *Cloud) { c.Bootstrap.Node = "mac-worker-1" }, "declared hub"},
		{"relay collision", func(c *Cloud) {
			n := c.Nodes["hub-1"]
			n.Voter = false
			c.Nodes["hub-2"] = n
		}, "unique relayDomain"},
		{"too many voters", func(c *Cloud) {
			for _, name := range []string{"hub-2", "hub-3", "hub-4"} {
				n := c.Nodes["hub-1"]
				n.RelayDomain = name + ".example.com"
				c.Nodes[name] = n
			}
		}, "exceed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := readValid(t)
			tc.edit(c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate error = %v, want %q", err, tc.want)
			}
		})
	}
	if err := Validate(nil); err == nil {
		t.Fatal("nil manifest accepted")
	}
}

func TestExistingCloudMayOmitTLSAndSSH(t *testing.T) {
	c := readValid(t)
	c.Bootstrap.TLSCertFile, c.Bootstrap.TLSKeyFile = "", ""
	n := c.Nodes["hub-1"]
	n.Connection.SSH = ""
	c.Nodes["hub-1"] = n
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(encoded) {
		t.Fatal("Validate mutated the manifest")
	}
}

func TestValidateNode(t *testing.T) {
	cases := []struct {
		name string
		node Node
	}{
		{"invalid-name!", Node{Role: "worker"}},
		{"worker", Node{Role: "unknown"}},
		{"worker", Node{Role: "worker", Voter: true}},
		{"worker", Node{Role: "worker", PublicIP: "203.0.113.10"}},
		{"worker", Node{Role: "worker", RelayDomain: "relay.example.com"}},
		{"worker", Node{Role: "worker", Connection: Connection{SSH: "root@localhost"}}},
		{"hub", Node{Role: "hub", PublicIP: "192.168.1.10", RelayDomain: "relay.example.com"}},
		{"hub", Node{Role: "hub", PublicIP: "127.0.0.1", RelayDomain: "relay.example.com"}},
		{"hub", Node{Role: "hub", PublicIP: "100.64.0.1", RelayDomain: "relay.example.com"}},
		{"hub", Node{Role: "hub", PublicIP: "203.0.113.10", RelayDomain: "bad domain"}},
		{"hub", Node{Role: "hub", PublicIP: "203.0.113.10", RelayDomain: "relay.example.com", Connection: Connection{SSH: "root@host;true"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateNode(tc.name, tc.node); err == nil {
				t.Fatalf("invalid node accepted: %+v", tc.node)
			}
		})
	}
}

func TestValidateLabels(t *testing.T) {
	for _, labels := range []map[string]string{
		nil,
		{"location": "home", "example.com/pool": "My_pool.1", "gpu": ""},
		{"kubernetes.io.example.com/location": "home"},
		{strings.Repeat("a", 63): strings.Repeat("z", 63)},
	} {
		if err := ValidateLabels(labels); err != nil {
			t.Fatalf("valid labels rejected: %v", err)
		}
	}
	for _, labels := range []map[string]string{
		{"": "x"},
		{"invalid key": "x"},
		{"a/b/c": "x"},
		{"example.com/": "x"},
		{"/key": "x"},
		{"Bad.example.com/key": "x"},
		{strings.Repeat("a", 64): "x"},
		{"key": strings.Repeat("a", 64)},
		{"key": "value with spaces"},
		{"key": "-leading"},
		{"key": "trailing-"},
		{"kubernetes.io/role": "master"},
		{"node-role.kubernetes.io/control-plane": ""},
		{"node-restriction.kubernetes.io/pool": "trusted"},
		{"example.k8s.io/role": "trusted"},
		{"k8s.io/role": "trusted"},
		{"connect.deepai.cloud/role": "hub"},
		{"internal.connect.deepai.cloud/role": "hub"},
	} {
		if err := ValidateLabels(labels); err == nil {
			t.Fatalf("invalid labels accepted: %v", labels)
		}
	}
}

func TestValidateSSH(t *testing.T) {
	for _, destination := range []string{"root@187.7.75.65", "ubuntu@hub.example.com", "deploy_user@hub", "root@[2001:db8::1]"} {
		if err := ValidateSSH(destination); err != nil {
			t.Fatalf("valid destination %q rejected: %v", destination, err)
		}
	}
	for _, destination := range []string{
		"", "hub", "@hub", "root@", "root@@hub", "-oProxyCommand@hub",
		"root@hub:22", "root@2001:db8::1", "root@[fe80::1%eth0]",
		"root@hub;touch /tmp/x", "root@hub$(echo x)", "root@hub`echo x`",
		"root@hub -oProxyCommand=evil", "root@hub\ncommand",
		"root@/tmp/socket", "root@-hostname", "root@hub\x00",
	} {
		if err := ValidateSSH(destination); err == nil {
			t.Fatalf("unsafe destination %q accepted", destination)
		}
	}
}

func TestImagePins(t *testing.T) {
	c := readValid(t)
	for _, image := range []string{
		"connect:v1", "registry.example.com:5000/connect:2026.10.20",
		"registry.example.com/connect@sha256:" + strings.Repeat("a", 64),
	} {
		c.Bootstrap.Image = image
		if err := Validate(c); err != nil {
			t.Fatalf("pinned image %q rejected: %v", image, err)
		}
	}
	for _, image := range []string{
		"connect:main", "connect:dev", "connect:Latest", "registry.example.com:5000/connect",
		"connect:v1;evil", "connect:v1\n", "connect@other:tag", "connect@@sha256:" + strings.Repeat("a", 64),
	} {
		c.Bootstrap.Image = image
		if err := Validate(c); err == nil {
			t.Fatalf("unpinned or unsafe image %q accepted", image)
		}
	}
}
