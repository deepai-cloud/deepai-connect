// Package cluster manages the one K3s cluster carried by Connect's host overlay.
// It deliberately never downloads or executes an installation script.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

const K3sVersion = "v1.36.4+k3s1"
const UnitName = "deepai-connect-k3s.service"
const AgentUnitName = "deepai-connect-agent.service"

// NodeRestriction prevents kubelet credentials from assigning this label.
const ProtectedRoleLabel = "connect.deepai.cloud.node-restriction.kubernetes.io/role"

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var ifaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var secureToken = regexp.MustCompile(`^K10[0-9a-f]{64}::[^\s]+$`)

// Config contains host-local installation state. JoinToken is a server or agent
// credential as appropriate; it is never included in argv or command errors.
type Config struct {
	Name             string   `json:"name"`
	Role             string   `json:"role"`
	OverlayIP        string   `json:"overlayIP"`
	OverlayInterface string   `json:"overlayInterface"`
	HostCIDR         string   `json:"hostCIDR"`
	PodCIDR          string   `json:"podCIDR"`
	ServiceCIDR      string   `json:"serviceCIDR"`
	ServerURL        string   `json:"serverURL,omitempty"`
	JoinToken        string   `json:"joinToken,omitempty"`
	K3sBinary        string   `json:"k3sBinary"`
	ConnectBinary    string   `json:"connectBinary,omitempty"`
	ConnectImage     string   `json:"connectImage,omitempty"`
	DataDir          string   `json:"dataDir"`
	SystemdDir       string   `json:"systemdDir"`
	AgentStateDir    string   `json:"agentStateDir,omitempty"`
	FirstHub         bool     `json:"firstHub"`
	Voter            bool     `json:"voter"`
	DesiredVoters    int      `json:"desiredVoters"`
	TLSSANs          []string `json:"tlsSANs,omitempty"`
}

type Runner interface {
	Run(context.Context, []byte, string, ...string) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, input []byte, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// stderr from kubectl/K3s can contain a submitted Secret or join credential.
		return nil, fmt.Errorf("%s failed: %w", filepath.Base(command), err)
	}
	return stdout.Bytes(), nil
}

type Manager struct {
	Config Config
	Runner Runner
	// Joined records that this installation has passed Kubernetes readiness at
	// least once. An API outage must never make it eligible for token rotation.
	Joined         bool
	restartPending bool
}

type savedInstallation struct {
	Config
	Joined         bool `json:"joined,omitempty"`
	RestartPending bool `json:"restartPending,omitempty"`
}

func New(c Config, r Runner) (*Manager, error) {
	if c.OverlayInterface == "" {
		c.OverlayInterface = "deepai0"
	}
	if c.HostCIDR == "" {
		c.HostCIDR = "100.64.0.0/10"
	}
	if c.PodCIDR == "" {
		c.PodCIDR = "10.42.0.0/16"
	}
	if c.ServiceCIDR == "" {
		c.ServiceCIDR = "10.43.0.0/16"
	}
	if c.DesiredVoters == 0 {
		c.DesiredVoters = 3
	}
	if c.K3sBinary == "" {
		c.K3sBinary = "/usr/local/bin/k3s"
	}
	if c.ConnectBinary == "" {
		c.ConnectBinary = "/usr/local/bin/deepai-connect"
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/deepai-connect/cluster"
	}
	if c.AgentStateDir == "" {
		c.AgentStateDir = filepath.Join(filepath.Dir(c.DataDir), "network")
	}
	if c.SystemdDir == "" {
		c.SystemdDir = "/etc/systemd/system"
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if r == nil {
		r = ExecRunner{}
	}
	return &Manager{Config: c, Runner: r}, nil
}
func Load(dir string, r Runner) (*Manager, error) {
	data, err := platform.ReadFile(filepath.Join(dir, "cluster.json"))
	if err != nil {
		return nil, err
	}
	var saved savedInstallation
	if err = json.Unmarshal(data, &saved); err != nil {
		return nil, errors.New("invalid saved cluster configuration")
	}
	if filepath.Clean(saved.DataDir) != filepath.Clean(dir) {
		return nil, errors.New("cluster state directory mismatch")
	}
	m, err := New(saved.Config, r)
	if err != nil {
		return nil, err
	}
	m.Joined, m.restartPending = saved.Joined, saved.RestartPending
	return m, nil
}
func (c Config) Validate() error {
	if !dnsLabel.MatchString(c.Name) {
		return errors.New("node name must be a lowercase DNS label")
	}
	if c.Role != "hub" && c.Role != "worker" {
		return errors.New("role must be hub or worker")
	}
	if !ifaceName.MatchString(c.OverlayInterface) {
		return errors.New("invalid overlay interface")
	}
	if c.DesiredVoters != 3 && c.DesiredVoters != 5 {
		return errors.New("desired etcd voters must be three or five (first hub bootstraps alone)")
	}
	if c.Role == "worker" && (c.FirstHub || c.Voter) {
		return errors.New("workers cannot be etcd voters or initialize a cluster")
	}
	if c.FirstHub && (!c.Voter || c.ServerURL != "" || c.JoinToken != "") {
		return errors.New("first hub must be a voter without a join server or credential")
	}
	ip, err := netip.ParseAddr(c.OverlayIP)
	if err != nil || !ip.Is4() {
		return errors.New("overlay IP must be an IPv4 address")
	}
	var ranges []netip.Prefix
	for _, value := range []string{c.HostCIDR, c.PodCIDR, c.ServiceCIDR} {
		p, e := netip.ParsePrefix(value)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() > 24 {
			return errors.New("host, pod and service ranges must be canonical IPv4 networks of /24 or larger")
		}
		for _, prior := range ranges {
			if p.Overlaps(prior) {
				return errors.New("host, pod and service address ranges must not overlap")
			}
		}
		ranges = append(ranges, p)
	}
	if ranges[0].Bits() < 10 || !netip.MustParsePrefix("100.64.0.0/10").Contains(ranges[0].Addr()) {
		return errors.New("host overlay range must lie within 100.64.0.0/10")
	}
	if !ranges[0].Contains(ip) {
		return errors.New("node IP is outside the host overlay range")
	}
	if !c.FirstHub {
		u, e := url.Parse(c.ServerURL)
		if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.Port() != "6443" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("join server must be an HTTPS overlay endpoint without a path")
		}
		peer, e := netip.ParseAddr(u.Hostname())
		if e != nil || !ranges[0].Contains(peer) {
			return errors.New("K3s join server must use an IP within the host overlay")
		}
		if !secureToken.MatchString(c.JoinToken) {
			return errors.New("a secure CA-pinned K3s join token is required")
		}
	}
	for _, path := range []string{c.K3sBinary, c.ConnectBinary, c.AgentStateDir, c.DataDir, c.SystemdDir} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return errors.New("K3s binary, data and systemd paths must be absolute")
		}
	}
	for _, san := range c.TLSSANs {
		if san == "" || strings.ContainsAny(san, "\r\n\x00 /") {
			return errors.New("invalid API certificate SAN")
		}
	}
	return nil
}

func (m *Manager) Save() error {
	if err := m.Config.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(savedInstallation{Config: m.Config, Joined: m.Joined, RestartPending: m.restartPending}, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFile(filepath.Join(m.Config.DataDir, "cluster.json"), append(data, '\n'), false)
}
func (m *Manager) kubeconfig() string {
	if m.Config.Role == "hub" {
		return filepath.Join(m.Config.DataDir, "kubeconfig")
	}
	return filepath.Join(m.Config.DataDir, "k3s", "agent", "kubelet.kubeconfig")
}
func (m *Manager) kubectl(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	flags := []string{"kubectl", "--kubeconfig", m.kubeconfig(), "--request-timeout=15s"}
	if m.Config.Role == "hub" {
		flags = append(flags, "--server=https://"+m.Config.OverlayIP+":6443")
	}
	return m.Runner.Run(ctx, input, m.Config.K3sBinary, append(flags, args...)...)
}

// K3sConfig is JSON, a YAML subset supported by K3s, avoiding shell expansion and
// YAML injection. Every hub is a control plane; non-voter hubs disable only etcd.
func (m *Manager) K3sConfig() ([]byte, error) {
	c := m.Config
	config := map[string]any{
		"node-name": c.Name, "node-ip": c.OverlayIP, "flannel-iface": c.OverlayInterface,
		"data-dir":   filepath.Join(c.DataDir, "k3s"),
		"node-label": []string{"connect.deepai.cloud/role=" + c.Role, "connect.deepai.cloud/voter=" + strconv.FormatBool(c.Voter)},
	}
	if c.Role == "hub" {
		config["advertise-address"] = c.OverlayIP
		config["bind-address"] = c.OverlayIP
		config["cluster-cidr"] = c.PodCIDR
		config["service-cidr"] = c.ServiceCIDR
		config["cluster-dns"] = clusterDNS(c.ServiceCIDR)
		config["flannel-backend"] = "vxlan"
		config["disable"] = []string{"servicelb"}
		config["write-kubeconfig"] = m.kubeconfig()
		config["write-kubeconfig-mode"] = "0600"
		config["tls-san"] = append([]string{c.OverlayIP}, c.TLSSANs...)
		config["secrets-encryption"] = true
		if c.FirstHub {
			config["cluster-init"] = true
		}
		if !c.Voter {
			config["disable-etcd"] = true
		}
	}
	if !c.FirstHub {
		config["server"] = c.ServerURL
		config["token-file"] = filepath.Join(c.DataDir, "join-token")
	}
	return json.MarshalIndent(config, "", "  ")
}
func clusterDNS(cidr string) string {
	p, _ := netip.ParsePrefix(cidr)
	ip := p.Addr()
	for range 10 {
		ip = ip.Next()
	}
	return ip.String()
}

// systemdQuote quotes a single literal argv element, including specifier and
// environment expansion. No shell interprets the command.
func systemdQuote(s string) string {
	return strconv.Quote(strings.ReplaceAll(strings.ReplaceAll(s, "%", "%%"), "$", "$$"))
}
func (m *Manager) Unit() string {
	mode := "agent"
	if m.Config.Role == "hub" {
		mode = "server"
	}
	return "[Unit]\nDescription=DeepAI Connect Kubernetes\nWants=network-online.target\nAfter=network-online.target " + AgentUnitName + "\nRequires=" + AgentUnitName + "\n\n[Service]\nType=notify\nDelegate=yes\nKillMode=process\nRestart=always\nRestartSec=5\nTimeoutStartSec=0\nLimitNOFILE=1048576\nTasksMax=infinity\nExecStartPre=" + systemdQuote(m.Config.ConnectBinary) + " agent-ready --dir " + systemdQuote(filepath.Dir(m.Config.AgentStateDir)) + "\nExecStart=" + systemdQuote(m.Config.K3sBinary) + " " + mode + " --config " + systemdQuote(filepath.Join(m.Config.DataDir, "k3s-config.yaml")) + "\n\n[Install]\nWantedBy=multi-user.target\n"
}

func (m *Manager) checkBinary(ctx context.Context) error {
	out, err := m.Runner.Run(ctx, nil, m.Config.K3sBinary, "--version")
	if err != nil {
		return fmt.Errorf("install the verified K3s %s binary at %s before continuing: %w", K3sVersion, m.Config.K3sBinary, err)
	}
	fields := strings.Fields(string(out))
	for _, field := range fields {
		if field == K3sVersion {
			return nil
		}
	}
	return fmt.Errorf("K3s must be pinned to %s", K3sVersion)
}
func (m *Manager) Install(ctx context.Context) error {
	// Tests use a fake Runner on any platform; actual host mutation is Linux only.
	if _, ok := m.Runner.(ExecRunner); ok && runtime.GOOS != "linux" {
		return errors.New("K3s hosts require Linux; run a macOS worker inside a Linux VM")
	}
	if err := m.Config.Validate(); err != nil {
		return err
	}
	if err := m.checkBinary(ctx); err != nil {
		return err
	}
	old, err := Load(m.Config.DataDir, m.Runner)
	rotateToken := false
	if err == nil {
		m.Joined, m.restartPending = old.Joined, old.restartPending
		before, _ := json.Marshal(old.Config)
		after, _ := json.Marshal(m.Config)
		if !bytes.Equal(before, after) {
			candidate := m.Config
			candidate.JoinToken = old.Config.JoinToken
			withoutToken, _ := json.Marshal(candidate)
			if old.Config.Role != "worker" || m.Config.Role != "worker" || !bytes.Equal(before, withoutToken) || strings.SplitN(old.Config.JoinToken, "::", 2)[0] != strings.SplitN(m.Config.JoinToken, "::", 2)[0] {
				return errors.New("existing installation differs; resume it or perform an explicit migration")
			}
			rotateToken = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	priorUnit, unitErr := platform.ReadFile(filepath.Join(m.Config.SystemdDir, UnitName))
	if unitErr == nil {
		if old == nil || err != nil {
			return errors.New("existing K3s unit has no local installation state; explicit recovery required")
		}
		if string(priorUnit) != m.Unit() {
			return errors.New("K3s systemd unit differs from this installation; refusing to overwrite it")
		}
	} else if !errors.Is(unitErr, os.ErrNotExist) {
		return unitErr
	}
	for _, name := range []string{"k3s.service", "k3s-agent.service"} {
		if _, err := os.Lstat(filepath.Join(m.Config.SystemdDir, name)); err == nil {
			return errors.New("existing standalone K3s installation requires explicit migration")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Fail before changing K3s when the bootstrap overlay has not started.
	if _, err = m.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", AgentUnitName); err != nil {
		return errors.New("host overlay agent must be healthy before installing K3s")
	}
	if rotateToken {
		joined, err := old.HasJoined(ctx)
		if err != nil {
			return err
		}
		if joined {
			return errors.New("joined worker credentials cannot be replaced; resume the saved installation")
		}
		// Journal the restart together with the new credential. If interrupted
		// before K3s consumes it, the next resume still reloads the token file.
		m.restartPending = true
	} else if m.restartPending {
		if _, err := m.HasJoined(ctx); err != nil {
			return err
		}
	}
	if err = m.Save(); err != nil {
		return err
	}
	config, err := m.K3sConfig()
	if err != nil {
		return err
	}
	if err = platform.WriteFile(filepath.Join(m.Config.DataDir, "k3s-config.yaml"), append(config, '\n'), false); err != nil {
		return err
	}
	if m.Config.JoinToken != "" {
		if err = platform.WriteFile(filepath.Join(m.Config.DataDir, "join-token"), []byte(m.Config.JoinToken+"\n"), false); err != nil {
			return err
		}
	}
	if err = platform.WriteFile(filepath.Join(m.Config.SystemdDir, UnitName), []byte(m.Unit()), false); err != nil {
		return err
	}
	if _, err = m.Runner.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if m.restartPending {
		if err = m.preparePendingWorkerCertificate(ctx); err != nil {
			return err
		}
		if _, err = m.Runner.Run(ctx, nil, "systemctl", "enable", UnitName); err != nil {
			return err
		}
		if _, err = m.Runner.Run(ctx, nil, "systemctl", "restart", "--no-block", UnitName); err != nil {
			return err
		}
	} else {
		if _, err = m.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "--no-block", UnitName); err != nil {
			return err
		}
	}
	if err = m.WaitReady(ctx); err != nil {
		return err
	}
	if m.Config.Role == "hub" {
		// A worker kubelet may spoof ordinary labels, but cannot grant itself
		// the placement label for pods carrying coordinator and cluster keys.
		if _, err = m.kubectl(ctx, nil, "label", "node", m.Config.Name, ProtectedRoleLabel+"=hub", "--overwrite"); err != nil {
			return err
		}
	}
	m.Joined, m.restartPending = true, false
	return m.Save()
}

// HasJoined checks durable completion first, then current readiness to cover a
// crash after joining but before saving completion. A failed probe means the
// pending installation has not been confirmed; it does not erase completion.
func (m *Manager) HasJoined(ctx context.Context) (bool, error) {
	if m.Joined {
		return true, nil
	}
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := m.ready(probe); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	m.Joined, m.restartPending = true, false
	if err := m.Save(); err != nil {
		return false, err
	}
	return true, nil
}

// WaitReady requires the Type=notify service to finish startup as well as the
// API's storage readiness (on hubs) and this node's Ready condition. A K3s worker can
// register a Ready kubelet before its network-policy controller has started.
func (m *Manager) WaitReady(ctx context.Context) error {
	// Pinned K3s waits for a fresh Ready heartbeat before starting NetworkPolicy.
	// Kubelet's first unchanged status report can take 7.5 minutes (the default
	// five-minute interval plus 50% jitter). Leave bounded room for startup too.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last error
	for {
		if _, err := m.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", UnitName); err != nil {
			last = fmt.Errorf("K3s service has not completed startup: %w", err)
		} else {
			last = m.ready(ctx)
		}
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("K3s did not become ready: %w (%v)", ctx.Err(), last)
		case <-ticker.C:
		}
	}
}
func (m *Manager) ready(ctx context.Context) error {
	if m.Config.Role == "hub" {
		out, err := m.kubectl(ctx, nil, "get", "--raw=/readyz")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(out)) != "ok" {
			return errors.New("Kubernetes storage readiness is not healthy")
		}
	}
	out, err := m.kubectl(ctx, nil, "get", "node", m.Config.Name, "-o", "json")
	if err != nil {
		return err
	}
	var node struct {
		Status struct {
			Conditions []struct{ Type, Status string }
			Addresses  []struct{ Type, Address string }
		}
	}
	if err = json.Unmarshal(out, &node); err != nil {
		return errors.New("invalid Kubernetes node status")
	}
	hasIP := false
	for _, a := range node.Status.Addresses {
		if a.Type == "InternalIP" && a.Address == m.Config.OverlayIP {
			hasIP = true
		}
	}
	if !hasIP {
		return errors.New("Kubernetes node has not registered its overlay address")
	}
	for _, c := range node.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			return nil
		}
	}
	return errors.New("Kubernetes node is not Ready")
}
func (m *Manager) JoinToken(ctx context.Context) (string, error) {
	if m.Config.Role != "hub" {
		return "", errors.New("only a hub can read cluster join credentials")
	}
	b, err := platform.ReadFile(filepath.Join(m.Config.DataDir, "k3s", "server", "token"))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if !secureToken.MatchString(token) {
		return "", errors.New("K3s did not produce a secure CA-pinned token")
	}
	return token, nil
}
