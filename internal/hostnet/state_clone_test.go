package hostnet

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
)

func TestStateCloneIsolatesMutableSnapshot(t *testing.T) {
	s, _ := testState(t, 1)
	peer, _ := testState(t, 2)
	s.Peers = []*tailcfg.Node{peer.Self, nil}
	s.Self.Tags = []string{"tag:hub"}
	s.Self.Hostinfo = (&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{s.PodCIDR}, NetInfo: &tailcfg.NetInfo{DERPLatency: map[string]float64{"1-v4": 0.1}}}).View()
	s.Self.CapMap = tailcfg.NodeCapMap{"test": {`{"enabled":true}`}}
	s.DERPMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {Nodes: []*tailcfg.DERPNode{{HostName: "relay.example"}}}}}
	s.PodRoutes = []netip.Prefix{s.PodCIDR}
	s.ApprovedRoutes = []netip.Prefix{s.ServiceCIDR}
	s.EgressSources = []netip.Prefix{s.Self.Addresses[0]}
	s.DirectHubEndpoints[peer.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	bits := 24
	s.PacketFilter = []tailcfg.FilterRule{{SrcIPs: []string{"192.0.2.0"}, SrcBits: []int{24}, IPProto: []int{6}, DstPorts: []tailcfg.NetPortRange{{IP: "192.0.2.0", Bits: &bits}}, CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{s.HostCIDR}, Caps: []tailcfg.PeerCapability{"legacy"}, CapMap: tailcfg.PeerCapMap{"test": {`{"enabled":true}`}}}}}}
	before, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	clone := s.Clone()
	if !reflect.DeepEqual(s, clone) {
		t.Fatal("clone changed snapshot contents")
	}
	clone.Self.Tags[0] = "changed"
	clone.Self.Addresses[0] = netip.Prefix{}
	clone.Self.CapMap["test"][0] = `{}`
	hi := clone.Self.Hostinfo.AsStruct()
	hi.RoutableIPs[0] = netip.Prefix{}
	hi.NetInfo.DERPLatency["1-v4"] = 1
	clone.Self.Hostinfo = hi.View()
	clone.Peers[0].AllowedIPs[0] = netip.Prefix{}
	clone.Peers[1] = s.Self
	clone.DERPMap.Regions[1].Nodes[0].HostName = "changed"
	clone.PodRoutes[0] = netip.Prefix{}
	clone.ApprovedRoutes[0] = netip.Prefix{}
	clone.EgressSources[0] = netip.Prefix{}
	clone.DirectHubEndpoints[peer.Self.Key][0] = netip.AddrPort{}
	clone.PacketFilter[0].SrcIPs[0] = "*"
	clone.PacketFilter[0].SrcBits[0] = 0
	clone.PacketFilter[0].IPProto[0] = 17
	clone.PacketFilter[0].DstPorts[0].IP = "*"
	*clone.PacketFilter[0].DstPorts[0].Bits = 0
	clone.PacketFilter[0].CapGrant[0].Dsts[0] = netip.Prefix{}
	clone.PacketFilter[0].CapGrant[0].Caps[0] = "changed"
	clone.PacketFilter[0].CapGrant[0].CapMap["test"][0] = `{}`
	after, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("mutating a clone changed the trusted input snapshot")
	}
}

func TestStateClonePreservesEmptyValues(t *testing.T) {
	for _, s := range []*State{nil, {}, {Peers: []*tailcfg.Node{}, PacketFilter: []tailcfg.FilterRule{}}} {
		if got := s.Clone(); !reflect.DeepEqual(got, s) {
			t.Fatalf("clone of %#v = %#v", s, got)
		}
	}
}

// Updating upstream policy fields requires reviewing clonePacketFilter too.
var _ = tailcfg.FilterRule(struct {
	SrcIPs   []string
	SrcBits  []int                  `json:",omitempty"`
	DstPorts []tailcfg.NetPortRange `json:",omitempty"`
	IPProto  []int                  `json:",omitempty"`
	CapGrant []tailcfg.CapGrant     `json:",omitempty"`
}{})

var _ = tailcfg.CapGrant(struct {
	Dsts   []netip.Prefix
	Caps   []tailcfg.PeerCapability `json:",omitempty"`
	CapMap tailcfg.PeerCapMap       `json:",omitempty"`
}{})
