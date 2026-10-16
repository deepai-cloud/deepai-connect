//go:build linux

package hostnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

// Exercise the nested kernel VXLAN -> userspace WireGuard -> kernel VXLAN
// path, including TCP segmentation/coalescing beyond the initial window.
// The existing small-packet acceptance test deliberately tests other paths.
func TestLinuxVXLANBulkTransfer(t *testing.T) {
	if os.Getenv("DEEPAI_CONNECT_PRIVILEGED_TEST") != "isolated-netns" {
		t.Skip("requires explicitly opted-in Linux namespace test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	interrupt, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupt, 3*time.Minute)
	defer cancel()
	h := &linuxAcceptance{t: t, ctx: ctx, root: t.TempDir()}
	h.assertHostUnchangedOnCleanup()
	h.createTopology()
	a, _ := h.makeState("a", 1)
	b, _ := h.makeState("b", 2)
	for i, s := range []*State{a, b} {
		s.PodRoutes = []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.42.%d.0/24", i+1))}
		s.Self.AllowedIPs = append(s.Self.AllowedIPs, s.PodRoutes...)
	}
	a.Peers, b.Peers = []*tailcfg.Node{b.Self.Clone()}, []*tailcfg.Node{a.Self.Clone()}
	a.DirectHubEndpoints[b.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("198.18.0.2:41641")}
	b.DirectHubEndpoints[a.Self.Key] = []netip.AddrPort{netip.MustParseAddrPort("198.18.0.1:41641")}
	for i, name := range []string{"a", "b"} {
		if err := SaveState(h.dir(name), []*State{a, b}[i]); err != nil {
			t.Fatal(err)
		}
		h.start(name, "agent")
		h.ready(name)
	}
	// Replace the initially advertised direct pod route with CNI-owned VXLAN
	// routes after agent startup, as Flannel does once its subnet leases arrive.
	for i, name := range []string{"a", "b"} {
		local, remote := i+1, 2-i
		h.ns(name, "ip", "link", "add", "flannel.1", "type", "vxlan", "id", "1", "local", fmt.Sprintf("100.64.0.%d", local), "remote", fmt.Sprintf("100.64.0.%d", remote), "dev", "deepai0", "dstport", "8472", "nolearning")
		h.ns(name, "ip", "link", "set", "flannel.1", "address", fmt.Sprintf("02:00:00:00:00:%02d", local), "mtu", "1230", "up")
		h.ns(name, "ip", "address", "add", fmt.Sprintf("10.42.%d.0/32", local), "dev", "flannel.1")
		h.ns(name, "ip", "neigh", "replace", fmt.Sprintf("10.42.%d.0", remote), "lladdr", fmt.Sprintf("02:00:00:00:00:%02d", remote), "nud", "permanent", "dev", "flannel.1")
		h.ns(name, "ip", "route", "replace", fmt.Sprintf("10.42.%d.0/24", remote), "via", fmt.Sprintf("10.42.%d.0", remote), "dev", "flannel.1", "onlink", "proto", "99")
	}
	for _, dev := range []string{"cni0", "pod0"} {
		h.ns("b", "ip", "link", "set", dev, "mtu", "1230")
	}
	h.ns("pod", "ip", "link", "set", "eth0", "mtu", "1230")
	for _, interfaces := range [][]string{{"flannel.1", "cni0"}, {"cni0", "flannel.1"}} {
		h.ns("b", "iptables", "-w", "-A", "FORWARD", "-i", interfaces[0], "-o", interfaces[1], "-j", "ACCEPT")
	}
	h.start("a", "http-vxlan")
	h.start("pod", "http")
	h.awaitHTTP("a", "http://10.42.2.5:18080/", "10.42.1.0")
	h.awaitHTTP("pod", "http://10.42.1.0:18080/", "10.42.2.5")
	for _, item := range []struct{ name, destination string }{{"a", "10.42.2.5"}, {"b", "10.42.1.0"}} {
		if got := h.ns(item.name, "ip", "route", "get", item.destination); !strings.Contains(got, "dev flannel.1") {
			t.Fatalf("bulk traffic bypasses VXLAN: %s", got)
		}
	}
	payload := acceptanceBulkPayload()
	path := filepath.Join(h.root, "payload.bin")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	beforeA, beforeB := h.vxlanBytes("a"), h.vxlanBytes("b")
	h.bulkBothDirections(path, payload)

	// Model kube-router's established-flow handling and ingress policy ordering.
	// Each curl creates a fresh connection, so old conntrack state cannot make
	// a denied request pass. Restore is tested immediately without retrying a
	// partial transfer or hiding failure behind a subsequent successful request.
	h.ns("b", "iptables", "-w", "-N", "KUBE-ROUTER-FORWARD")
	h.ns("b", "iptables", "-w", "-A", "KUBE-ROUTER-FORWARD", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
	h.ns("b", "iptables", "-w", "-A", "KUBE-ROUTER-FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
	h.ns("b", "iptables", "-w", "-I", "FORWARD", "1", "-j", "KUBE-ROUTER-FORWARD")
	deny := []string{"KUBE-ROUTER-FORWARD", "-s", "10.42.1.0/32", "-d", "10.42.2.5/32", "-j", "DROP"}
	for round := range 2 {
		h.ns("b", append([]string{"iptables", "-w", "-A"}, deny...)...)
		h.assertHTTPDenied("a", "http://10.42.2.5:18080/bulk")
		counters := h.ns("b", "iptables", "-w", "-v", "-x", "-n", "-L", "KUBE-ROUTER-FORWARD")
		dropped := false
		for line := range strings.SplitSeq(counters, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 9 && fields[2] == "DROP" && strings.TrimSuffix(fields[7], "/32") == "10.42.1.0" && strings.TrimSuffix(fields[8], "/32") == "10.42.2.5" {
				packets, _ := strconv.ParseUint(fields[0], 10, 64)
				dropped = packets > 0
			}
		}
		if !dropped {
			t.Fatalf("denied HTTP did not hit the intended policy DROP: %s", counters)
		}
		// Independent pod-initiated traffic must remain usable under the deny.
		h.bulkTransfer("pod", "http://10.42.1.0:18080/bulk", "", payload)
		h.ns("b", append([]string{"iptables", "-w", "-D"}, deny...)...)
		h.bulkBothDirections(path, payload)
		t.Logf("PASS: VXLAN bulk transfer after policy deny/remove round %d", round+1)
	}
	for _, item := range []struct {
		name   string
		before [2]uint64
	}{{"a", beforeA}, {"b", beforeB}} {
		after := h.vxlanBytes(item.name)
		for i, direction := range []string{"RX", "TX"} {
			if after[i] < item.before[i]+uint64(len(payload)) {
				t.Fatalf("%s VXLAN %s carried too little payload: before=%d after=%d", item.name, direction, item.before[i], after[i])
			}
		}
		t.Logf("%s VXLAN bytes: RX=%d TX=%d", item.name, after[0]-item.before[0], after[1]-item.before[1])
	}
	h.assertCNI()
	t.Logf("PASS: 256KiB SHA256-checked uploads/downloads both ways through real VXLAN over Connect TUN; SHA256=%x", sha256.Sum256(payload))
}

func acceptanceBulkPayload() []byte {
	b := make([]byte, 256<<10)
	for i := range b {
		b[i] = byte(i*31 + 17)
	}
	return b
}

func acceptanceBulkHTTP(w http.ResponseWriter, r *http.Request) {
	payload := acceptanceBulkPayload()
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	case http.MethodPost:
		digest := sha256.New()
		n, err := io.Copy(digest, io.LimitReader(r.Body, int64(len(payload))+1))
		want := sha256.Sum256(payload)
		if err != nil || n != int64(len(payload)) || !slices.Equal(digest.Sum(nil), want[:]) {
			http.Error(w, "incomplete or corrupt upload", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintln(w, hex.EncodeToString(digest.Sum(nil)))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *linuxAcceptance) bulkBothDirections(path string, payload []byte) {
	for _, request := range []struct{ name, url string }{{"a", "http://10.42.2.5:18080/bulk"}, {"pod", "http://10.42.1.0:18080/bulk"}} {
		h.bulkTransfer(request.name, request.url, "", payload)
		h.bulkTransfer(request.name, request.url, path, payload)
	}
}

func (h *linuxAcceptance) bulkTransfer(name, url, uploadPath string, payload []byte) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 16*time.Second)
	defer cancel()
	args := []string{"netns", "exec", h.names[name], "curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "15"}
	if uploadPath != "" {
		args = append(args, "--data-binary", "@"+uploadPath)
	}
	args = append(args, url)
	cmd := exec.CommandContext(ctx, "ip", args...)
	// Keep diagnostic stderr separate so a failed partial body is never
	// mistaken for payload and so large successful bodies aren't logged.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	body, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("%s -> %s bulk transfer: %v, received %d bytes: %s", name, url, err, len(body), stderr.String())
	}
	want := sha256.Sum256(payload)
	if uploadPath != "" {
		if strings.TrimSpace(string(body)) != hex.EncodeToString(want[:]) {
			h.t.Fatalf("%s upload digest mismatch: %q", name, body)
		}
	} else if len(body) != len(payload) || sha256.Sum256(body) != want {
		h.t.Fatalf("%s downloaded %d bytes with digest %x, want %d bytes with digest %x", name, len(body), sha256.Sum256(body), len(payload), want)
	}
}

func (h *linuxAcceptance) vxlanBytes(name string) [2]uint64 {
	h.t.Helper()
	var links []struct {
		Stats struct {
			RX struct{ Bytes uint64 }
			TX struct{ Bytes uint64 }
		} `json:"stats64"`
	}
	if err := json.Unmarshal([]byte(h.ns(name, "ip", "-json", "-statistics", "link", "show", "flannel.1")), &links); err != nil || len(links) != 1 {
		h.t.Fatalf("read VXLAN link counters: %v", err)
	}
	return [2]uint64{links[0].Stats.RX.Bytes, links[0].Stats.TX.Bytes}
}
