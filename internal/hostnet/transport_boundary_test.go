package hostnet

import (
	"errors"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func TestTransportBoundaryRollsBackOnlyItsPartialInstall(t *testing.T) {
	missing := exec.Command("sh", "-c", "exit 1").Run()
	if missing == nil {
		t.Fatal("missing exit status fixture")
	}
	r := &hostRouter{port: DefaultPort, protected: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
	rules := r.transportBoundaryRules()
	preexisting := strings.Join(rules[0], " ")
	installed := map[string]bool{preexisting: true, "unrelated": true}
	added := 0
	r.run = func(name string, args ...string) ([]byte, error) {
		key := strings.Join(args[4:], " ")
		switch args[3] {
		case "-C":
			if !installed[key] {
				return nil, missing
			}
		case "-I":
			added++
			if added == 2 {
				return nil, errors.New("injected firewall install failure")
			}
			installed[key] = true
		case "-D":
			delete(installed, key)
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return nil, nil
	}
	if err := r.installTransportBoundary(); err == nil {
		t.Fatal("partial install reported success")
	}
	if len(installed) != 2 || !installed[preexisting] || !installed["unrelated"] {
		t.Fatalf("rollback changed preexisting firewall state: %v", installed)
	}
	if err := r.removeTransportBoundary(); err != nil {
		t.Fatal(err)
	}
	if err := r.removeTransportBoundary(); err != nil || len(installed) != 1 || !installed["unrelated"] {
		t.Fatalf("repeat cleanup changed unrelated rules: %v %v", err, installed)
	}
}
