package hostnet

import (
	"errors"
	"os/exec"
	"strconv"

	"tailscale.com/tsconst"
)

// Map sanitation alone cannot prevent a stale peer's CallMeMaybe or a disco
// pong from teaching magicsock a recursively routed endpoint. Reject only the
// agent's transport datagrams to/from configured cluster ranges, before they
// reach its UDP socket or enter the overlay/CNI. Ordinary pod/host traffic and
// unrelated forwarded WireGuard datagrams are unaffected.
func (r *hostRouter) transportBoundaryRules() [][]string {
	var rules [][]string
	port := strconv.Itoa(int(r.port))
	for _, prefix := range r.protected {
		if !prefix.IsValid() || prefix.Bits() == 0 {
			continue
		}
		rules = append(rules,
			[]string{"OUTPUT", "-p", "udp", "--sport", port, "-d", prefix.String(), "-m", "comment", "--comment", "deepai-connect-underlay", "-j", "DROP"},
			// Linux magicsock uses SO_MARK on every UDP socket, including an
			// ephemeral fallback when its requested port is occupied. Where
			// SO_MARK is unavailable, upstream binds the socket to the physical
			// default interface, which also prevents overlay/CNI recursion.
			[]string{"OUTPUT", "-p", "udp", "-m", "mark", "--mark", tsconst.LinuxBypassMark + "/" + tsconst.LinuxFwmarkMask, "-d", prefix.String(), "-m", "comment", "--comment", "deepai-connect-underlay", "-j", "DROP"},
			[]string{"PREROUTING", "-p", "udp", "--dport", port, "-s", prefix.String(), "-m", "addrtype", "--dst-type", "LOCAL", "-m", "comment", "--comment", "deepai-connect-underlay", "-j", "DROP"},
		)
	}
	return rules
}

func (r *hostRouter) installTransportBoundary() (err error) {
	var added [][]string
	defer func() {
		if err != nil {
			// Preserve rules that predated this attempt; only roll back exact
			// new rules if an interrupted installation cannot finish.
			err = errors.Join(err, r.removeTransportRules(added))
		}
	}()
	for _, rule := range r.transportBoundaryRules() {
		if _, checkErr := r.run("iptables", append([]string{"-w", "-t", "raw", "-C"}, rule...)...); checkErr != nil {
			if _, err = r.run("iptables", append([]string{"-w", "-t", "raw", "-I"}, rule...)...); err != nil {
				return err
			}
			added = append(added, rule)
		}
	}
	return nil
}

func (r *hostRouter) removeTransportBoundary() error {
	return r.removeTransportRules(r.transportBoundaryRules())
}

func (r *hostRouter) removeTransportRules(rules [][]string) error {
	var result error
	for _, rule := range rules {
		_, err := r.run("iptables", append([]string{"-w", "-t", "raw", "-C"}, rule...)...)
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			continue // The exact owned rule is already absent.
		}
		if err == nil {
			_, err = r.run("iptables", append([]string{"-w", "-t", "raw", "-D"}, rule...)...)
		}
		result = errors.Join(result, err)
	}
	return result
}
