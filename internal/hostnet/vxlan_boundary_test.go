package hostnet

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestVXLANBoundaryReconcileNeverRemovesExistingGuard(t *testing.T) {
	rule := []string{"!", "-i", "deepai0", "-j", "DROP"}
	other := []string{"-s", "192.0.2.1", "-j", "ACCEPT"}
	// A failed earlier reconciliation can leave its temporary exact guard.
	temporary := []string{"!", "-i", "deepai0", "-m", "comment", "--comment", "deepai-connect-vxlan-reconcile", "-j", "DROP"}
	rules := [][]string{slices.Clone(rule), other, slices.Clone(rule), temporary}
	mutations := 0
	run := func(name string, args ...string) ([]byte, error) {
		if name != "iptables" || !slices.Equal(args[:3], []string{"-w", "-t", "raw"}) {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		switch args[3] {
		case "-S":
			selected := rules
			var lines []string
			for _, r := range selected {
				quoted := slices.Clone(r)
				for i := 0; i+1 < len(quoted); i++ {
					if quoted[i] == "--comment" {
						quoted[i+1] = `"` + quoted[i+1] + `"`
					}
				}
				lines = append(lines, "-A DEEPAI-VXLAN "+strings.Join(quoted, " "))
			}
			return []byte(strings.Join(lines, "\n")), nil
		case "-I":
			rules = append([][]string{slices.Clone(args[5:])}, rules...)
		case "-D":
			found := slices.IndexFunc(rules, func(r []string) bool { return slices.Equal(r, args[5:]) })
			if found < 0 {
				return nil, errors.New("missing exact rule")
			}
			rules = slices.Delete(rules, found, found+1)
		default:
			return nil, errors.New("unexpected operation")
		}
		mutations++
		if len(rules) == 0 || !(slices.Equal(rules[0], rule) || (strings.HasPrefix(strings.Join(rules[0], " "), "! -i deepai0 -m comment --comment deepai-connect-vxlan-reconcile") && slices.Equal(rules[0][len(rules[0])-2:], []string{"-j", "DROP"}))) {
			t.Fatal("listener was left unguarded during reconciliation")
		}
		return nil, nil
	}
	if err := firstExactFirewallRule(run, "raw", "DEEPAI-VXLAN", rule); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(rules) != fmt.Sprint([][]string{rule, other}) {
		t.Fatalf("unrelated rule changed or duplicates survived: %v", rules)
	}
	before := mutations
	if err := firstExactFirewallRule(run, "raw", "DEEPAI-VXLAN", rule); err != nil {
		t.Fatal(err)
	}
	if mutations != before {
		t.Fatal("already installed boundary was mutated")
	}
}

func TestVXLANBoundaryDeletesOnlyExactOwnedRules(t *testing.T) {
	canonical := []string{"!", "-i", "deepai0", "-j", "DROP"}
	run := func(name string, args ...string) ([]byte, error) {
		if args[3] == "-S" {
			return []byte("-A DEEPAI-VXLAN -j ACCEPT\n-A DEEPAI-VXLAN ! -i deepai0 -j DROP"), nil
		}
		if args[3] == "-D" {
			if !slices.Equal(args[5:], canonical) && !strings.Contains(strings.Join(args[5:], " "), "--comment deepai-connect-vxlan-reconcile -j DROP") {
				t.Fatalf("deletion could affect another owner's concurrently shifted rule: %v", args)
			}
		}
		return nil, nil
	}
	if err := firstExactFirewallRule(run, "raw", "DEEPAI-VXLAN", canonical); err != nil {
		t.Fatal(err)
	}
}
