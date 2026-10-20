package unified

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

func gatewayTestFilter(t *testing.T, rules []tailcfg.FilterRule) *filter.Filter {
	t.Helper()
	matches, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	var all netipx.IPSetBuilder
	all.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	local, err := all.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	return filter.New(matches, nil, local, nil, nil, func(string, ...any) {})
}

func TestGatewayInternetGrantPreservesRestrictedPrivatePolicy(t *testing.T) {
	private := tailcfg.FilterRule{SrcIPs: []string{"100.96.0.2/32"}, DstPorts: []tailcfg.NetPortRange{{IP: "10.42.1.9/32", Ports: tailcfg.PortRange{First: 443, Last: 443}}}}
	state := &coordinator.State{Policy: []tailcfg.FilterRule{private}}
	if err := addGatewayInternetPolicy(state, "100.96.0.0/16", "10.42.0.0/16", "10.43.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.Policy[0], private) {
		t.Fatal("gateway changed the existing private ACL")
	}
	f := gatewayTestFilter(t, state.Policy)
	for _, check := range []struct {
		source, destination string
		port                uint16
		allow               bool
	}{
		{"100.96.0.2", "10.42.1.9", 443, true},
		{"100.96.0.2", "10.42.1.9", 80, false},
		{"100.96.0.2", "10.42.1.10", 443, false},
		{"100.96.0.3", "10.42.1.9", 443, false},
		{"100.96.0.2", "100.96.0.1", 6443, false},
		{"10.42.2.5", "10.43.0.1", 443, false},
		{"100.96.0.2", "1.1.1.1", 80, true},
		{"100.96.0.2", "8.8.8.8", 443, true},
		{"10.42.2.5", "1.1.1.1", 80, true},
		{"10.42.2.5", "8.8.8.8", 443, true},
		{"10.99.0.1", "1.1.1.1", 443, false},
	} {
		if got := f.CheckTCP(netip.MustParseAddr(check.source), netip.MustParseAddr(check.destination), check.port); (got == filter.Accept) != check.allow {
			t.Errorf("%s -> %s:%d = %s, allow=%t", check.source, check.destination, check.port, got, check.allow)
		}
	}
}

func TestGatewayInternetGrantExcludesSpecialAndConfiguredRanges(t *testing.T) {
	state := new(coordinator.State)
	if err := addGatewayInternetPolicy(state, "11.0.0.0/16", "12.0.0.0/16", "13.0.0.0/16"); err != nil {
		t.Fatal(err)
	}
	f := gatewayTestFilter(t, state.Policy)
	for _, destination := range []string{
		"0.0.0.1", "10.255.255.254", "100.64.0.1", "100.127.255.254",
		"127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.254",
		"192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1",
		"198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "239.255.255.254", "240.0.0.1", "255.255.255.255",
		"11.0.0.9", "12.0.0.9", "13.0.0.9",
	} {
		ip := netip.MustParseAddr(destination)
		if got := f.CheckTCP(netip.MustParseAddr("11.0.0.2"), ip, 443); got == filter.Accept {
			t.Errorf("gateway allowed protected destination %s", ip)
		}
		for _, dst := range state.Policy[0].DstPorts {
			if netip.MustParsePrefix(dst.IP).Contains(ip) {
				t.Errorf("generated grant includes excluded destination %s in %s", ip, dst.IP)
			}
		}
	}
	if got := f.CheckTCP(netip.MustParseAddr("11.0.0.2"), netip.MustParseAddr("11.1.0.1"), 443); got != filter.Accept {
		t.Fatal("configured prefix exclusion escaped its exact boundary")
	}
}

func TestGatewayInternetGrantIsIdempotentAndValidatesBeforeMutation(t *testing.T) {
	state := new(coordinator.State)
	for range 3 {
		if err := addGatewayInternetPolicy(state, "100.96.0.0/16", "10.42.0.0/16", "10.43.0.0/16"); err != nil {
			t.Fatal(err)
		}
	}
	if len(state.Policy) != 1 {
		t.Fatal("repeated gateway enablement duplicated shared policy")
	}
	before := state.Policy
	for _, invalid := range []string{"", "invalid", "::/0", "0.0.0.0/0", "10.42.0.1/16"} {
		if err := addGatewayInternetPolicy(state, "100.96.0.0/16", invalid, "10.43.0.0/16"); err == nil {
			t.Errorf("accepted invalid cluster range %q", invalid)
		}
		if !reflect.DeepEqual(before, state.Policy) {
			t.Fatal("invalid gateway configuration changed packet policy")
		}
	}
}

func TestGatewayEnablePreservesCloudManagedPolicy(t *testing.T) {
	restricted := []tailcfg.FilterRule{{
		SrcIPs:   []string{"100.96.0.2/32"},
		DstPorts: []tailcfg.NetPortRange{{IP: "1.1.1.1/32", Ports: tailcfg.PortRange{First: 443, Last: 443}}},
	}}
	for name, policy := range map[string][]tailcfg.FilterRule{"deny-all": {}, "restricted": restricted} {
		t.Run(name, func(t *testing.T) {
			state := &coordinator.State{Policy: policy}
			r := enrollment.Registry{
				Cluster: enrollment.Cluster{ID: "cloud-test"},
				Invites: map[string]*enrollment.Invite{}, Members: map[string]*enrollment.Member{},
				Cloud: &enrollment.DesiredCloud{Revision: "unchanged", Policy: policy, Spec: cloudconfig.Cloud{Network: cloudconfig.Network{PacketPolicyFile: "network/policy.json"}}},
			}
			if err := enrollment.WriteRegistry(state, r); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(state)
			if err := addGatewayInternetPolicy(state, "100.96.0.0/16", "10.42.0.0/16", "10.43.0.0/16"); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(state)
			if string(after) != string(before) {
				t.Fatal("gateway enable changed cloud-owned policy or revision")
			}
			f := gatewayTestFilter(t, state.Policy)
			if f.CheckTCP(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("8.8.8.8"), 443) == filter.Accept ||
				f.CheckTCP(netip.MustParseAddr("100.96.0.3"), netip.MustParseAddr("1.1.1.1"), 443) == filter.Accept {
				t.Fatal("gateway enable broadened declared egress")
			}
			if got := f.CheckTCP(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("1.1.1.1"), 443); (got == filter.Accept) != (name == "restricted") {
				t.Fatal("gateway enable changed explicitly declared egress")
			}
		})
	}
}

func TestGatewayPolicyRejectsMalformedEnrollmentAndKeepsLegacyBehavior(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, []byte(`null`), []byte(`{}`), []byte(`{`)} {
		state := &coordinator.State{Extensions: map[string]json.RawMessage{enrollment.Extension: raw}}
		if err := addGatewayInternetPolicy(state, "100.96.0.0/16", "10.42.0.0/16", "10.43.0.0/16"); err == nil || state.Policy != nil {
			t.Fatal("malformed enrollment allowed a policy mutation")
		}
	}
	for _, desired := range []*enrollment.DesiredCloud{nil, {Spec: cloudconfig.Cloud{}}} {
		state := new(coordinator.State)
		if err := enrollment.WriteRegistry(state, enrollment.Registry{
			Cluster: enrollment.Cluster{ID: "legacy"},
			Invites: map[string]*enrollment.Invite{}, Members: map[string]*enrollment.Member{},
			Cloud: desired,
		}); err != nil {
			t.Fatal(err)
		}
		if err := addGatewayInternetPolicy(state, "100.96.0.0/16", "10.42.0.0/16", "10.43.0.0/16"); err != nil || len(state.Policy) != 1 {
			t.Fatal("unmanaged cloud policy lost legacy Internet grant", err)
		}
	}
}
