package hostnet

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"tailscale.com/wgengine/router"
)

func TestRouterPreservesCNIAndOtherFirewallRules(t *testing.T) {
	var calls [][]string
	r := &hostRouter{iface: "deepai0", run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "ip" && len(args) > 0 && args[0] == "-json" {
			return []byte(`[{"dev":"cni0","protocol":"kernel"}]`), nil
		}
		if name == "iptables" && len(args) > 1 && args[1] == "-C" {
			return nil, errors.New("not present")
		}
		return nil, nil
	}}
	if err := r.Up(); err != nil {
		t.Fatal(err)
	}
	err := r.Set(&router.Config{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.42.1.0/24")}})
	if err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("CNI route was not protected: %v", err)
	}
	_ = r.Close()
	for _, c := range calls {
		for _, arg := range c {
			if arg == "-F" || arg == "flush" {
				t.Fatalf("unscoped flush: %v", c)
			}
		}
		if len(c) > 2 && c[0] == "ip" && c[1] == "route" && c[2] == "add" {
			t.Fatalf("overwrote CNI route: %v", c)
		}
	}
}

func TestRouterRouteRevocationIsScoped(t *testing.T) {
	var calls [][]string
	present := false
	r := &hostRouter{iface: "deepai0", run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if slices.Contains(args, "-json") && present {
			return []byte(`[{"dev":"deepai0","protocol":"186"}]`), nil
		}
		if slices.Contains(args, "add") {
			present = true
		}
		if slices.Contains(args, "del") {
			present = false
		}
		return []byte("[]"), nil
	}}
	p := netip.MustParsePrefix("100.64.0.2/32")
	if err := r.Set(&router.Config{Routes: []netip.Prefix{p}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Set(nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"ip", "route", "del", p.String(), "dev", "deepai0", "proto", "186"}
	if !reflect.DeepEqual(calls[len(calls)-1], want) {
		t.Fatalf("delete = %v", calls[len(calls)-1])
	}
}

func TestRouteWithdrawalToleratesOnlyProvenCNITakeover(t *testing.T) {
	for _, scenario := range []string{"absent", "replaced", "raced", "still-owned", "read-failed"} {
		t.Run(scenario, func(t *testing.T) {
			p := netip.MustParsePrefix("10.42.2.0/24")
			reads, deletes := 0, 0
			r := &hostRouter{iface: "deepai0", routes: []netip.Prefix{p}, run: func(name string, args ...string) ([]byte, error) {
				if slices.Contains(args, "-json") {
					reads++
					if scenario == "read-failed" {
						return nil, errors.New("permission denied")
					}
					if scenario == "absent" {
						return []byte("[]"), nil
					}
					if scenario == "replaced" || (scenario == "raced" && reads > 1) {
						return []byte(`[{"dev":"flannel.1","protocol":"3"}]`), nil
					}
					return []byte(`[{"dev":"deepai0","protocol":"186"}]`), nil
				}
				if slices.Contains(args, "del") {
					deletes++
					return nil, errors.New("route deletion failed")
				}
				return nil, nil
			}}
			err := r.Set(nil)
			wantError := scenario == "still-owned" || scenario == "read-failed"
			if (err != nil) != wantError {
				t.Fatalf("unexpected result %v", err)
			}
			if !wantError && len(r.routes) != 0 {
				t.Fatal("stale bookkeeping survived map withdrawal")
			}
			if (scenario == "absent" || scenario == "replaced") && deletes != 0 {
				t.Fatal("attempted to delete an unowned route")
			}
			if wantError && len(r.routes) != 1 {
				t.Fatal("failed route removal was silently committed")
			}
		})
	}
}

func TestRouterAdoptsOwnRouteWithNamedProtocolDatabase(t *testing.T) {
	added := false
	r := &hostRouter{iface: "deepai0", run: func(name string, args ...string) ([]byte, error) {
		if slices.Contains(args, "-json") {
			// Linux iproute2 renders protocol 186 as "bgp" by default.
			if slices.Contains(args, "-N") {
				return []byte(`[{"dev":"deepai0","protocol":"186"}]`), nil
			}
			return []byte(`[{"dev":"deepai0","protocol":"bgp"}]`), nil
		}
		if slices.Contains(args, "add") {
			added = true
		}
		return nil, nil
	}}
	p := netip.MustParsePrefix("100.64.0.2/32")
	if err := r.Set(&router.Config{Routes: []netip.Prefix{p}}); err != nil {
		t.Fatalf("existing owned route was rejected: %v", err)
	}
	if added || !slices.Contains(r.routes, p) {
		t.Fatal("existing owned route was not adopted without replacing it")
	}
}
