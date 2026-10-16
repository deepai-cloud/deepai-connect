package unified

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

// addGatewayInternetPolicy grants public IPv4 forwarding without broadening
// existing private-network permissions. Packet policy is additive, so allowing
// 0/0 here would silently override an operator's restrictive private ACLs.
// The generated grant is shared by gateways and is retained when one disables
// its advertised default route; policy removal remains an explicit admin action.
func addGatewayInternetPolicy(state *coordinator.State, hostCIDR, podCIDR, serviceCIDR string) error {
	if state == nil {
		return errors.New("gateway policy requires network state")
	}
	var internet netipx.IPSetBuilder
	internet.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	for _, raw := range []string{hostCIDR, podCIDR, serviceCIDR} {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
			return fmt.Errorf("gateway policy requires a canonical non-default IPv4 cluster range: %q", raw)
		}
		internet.RemovePrefix(p)
	}
	// Exclude non-public and special-use IPv4 ranges. Conservatively exclude
	// entire reserved blocks, including documentation and benchmarking ranges,
	// rather than treating their isolated global-use exceptions as Internet.
	for _, raw := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	} {
		internet.RemovePrefix(netip.MustParsePrefix(raw))
	}
	public, err := internet.IPSet()
	if err != nil {
		return fmt.Errorf("construct public gateway destinations: %w", err)
	}
	rule := tailcfg.FilterRule{SrcIPs: []string{hostCIDR, podCIDR}}
	for _, p := range public.Prefixes() {
		rule.DstPorts = append(rule.DstPorts, tailcfg.NetPortRange{IP: p.String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}})
	}
	for _, existing := range state.Policy {
		if reflect.DeepEqual(existing, rule) {
			return nil
		}
	}
	state.Policy = append(state.Policy, rule)
	return nil
}
