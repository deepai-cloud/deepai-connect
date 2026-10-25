// Package desktop administers an existing Connect hub over authenticated SSH.
// It needs neither a local Kubernetes client nor a host network installation.
package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"golang.org/x/term"
)

const defaultStateDir = "/var/lib/deepai-connect"

var errNoHub = errors.New("no hub configured; run deepai-connect setup --hub USER@HOST")

type Config struct {
	Hub       string `json:"hub"`
	StateDir  string `json:"stateDir"`
	VM        string `json:"vm,omitempty"`
	OverlayIP string `json:"overlayIP"`
}

// Injectable for tests; captured commands never include output in errors because
// kubeconfig export may return private keys.
var runProcess = execProcess

func execProcess(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return nil
}

var Commands = []string{"setup", "status", "network", "nodes", "vm", "doctor", "containers", "logs", "kubectl", "kubeconfig", "tunnel"}

func Handles(command string) bool { return slices.Contains(Commands, command) }

func PrintStart(out io.Writer) {
	fmt.Fprintln(out, "deepai-connect — manage your private cloud")
	if cfg, err := loadConfig(); err == nil {
		fmt.Fprintf(out, "\nSaved hub: %s (not checked)\n", cfg.Hub)
	} else if !errors.Is(err, errNoHub) {
		fmt.Fprintf(out, "\nSaved hub unavailable: %v\nRun deepai-connect setup --hub USER@HOST to configure access.\n", err)
	}
	fmt.Fprint(out, `
Start:
  setup --hub USER@HOST   Configure access to your hub

Everyday:
  status                 See what is running
  network                See device IPs, paths and latency
  nodes                  See node CPU, memory and storage
  vm resources           See the local worker VM's resource grant
  containers             List workloads
  logs POD -n NAMESPACE  Read workload logs
  doctor                 Find problems and the next step

Command help: deepai-connect help COMMAND
All commands: deepai-connect --help
`)
}

func printCommandHelp(command string) bool {
	help := map[string]string{
		"status": `Usage: deepai-connect status
Show the configured hub's mesh snapshot, cluster nodes and optional local VM.
Administration uses SSH; setup does not join this computer to the mesh.

Next: deepai-connect containers
If something fails: deepai-connect doctor`,
		"doctor": `Usage: deepai-connect doctor
Check the configured hub's mesh, services, API, nodes and system workloads.
Network observations provide warnings; failed health checks exit nonzero.

Example: deepai-connect doctor
Connections and latency: deepai-connect network`,
		"nodes": nodesHelp,
		"containers": `Usage: deepai-connect containers [-n NAMESPACE] [kubectl get flags]
List workloads (Kubernetes pods) through the configured hub over SSH.

Examples:
  deepai-connect containers -n default
  deepai-connect logs POD -n NAMESPACE
  deepai-connect kubectl exec -it POD -n NAMESPACE -- sh
The terminal example requires sh in the container; use -c for a specific container.`,
		"logs": `Usage: deepai-connect logs POD [-n NAMESPACE] [-c CONTAINER] [-f] [kubectl logs flags]
Read workload logs through the configured hub over SSH.

Find a pod: deepai-connect containers
Example: deepai-connect logs POD -n NAMESPACE -f`,
		"kubectl": `Usage: deepai-connect kubectl [kubectl arguments]
Run kubectl on the configured hub over SSH. File paths and listeners are on the hub.
For local files or port-forwarding, use kubeconfig install and tunnel with local kubectl.

Examples:
  deepai-connect kubectl describe pod POD -n NAMESPACE
  deepai-connect kubectl exec -it POD -n NAMESPACE -- sh
The terminal example requires sh in the container; use -c for a specific container.`,
		"network": networkHelp,
		"vm":      vmHelp,
	}
	if text, ok := help[command]; ok {
		fmt.Println(text)
		return true
	}
	return false
}

// reportFlags preserves structured failures even when an invalid flag appears
// before --json. Help still uses the normal flag output and never emits JSON.
func reportFlags(fs *flag.FlagSet, args []string, out io.Writer) (*bool, func(error) error, error) {
	asJSON := fs.Bool("json", false, "structured output")
	fail := func(err error) error {
		if *asJSON {
			_ = json.NewEncoder(out).Encode(struct {
				SchemaVersion int    `json:"schemaVersion"`
				Error         string `json:"error"`
			}{1, err.Error()})
		}
		return err
	}
	err := fs.Parse(args)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		for _, arg := range args {
			if arg == "--" {
				break
			}
			switch arg {
			case "--json", "--json=true":
				*asJSON = true
			case "--json=false":
				*asJSON = false
			}
		}
		err = fail(err)
	}
	return asJSON, fail, err
}

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("a desktop administration command is required")
	}
	if (args[0] != "kubectl" || len(args) == 2) && requestsHelp(args[1:]) && printCommandHelp(args[0]) {
		return nil
	}
	var err error
	switch args[0] {
	case "setup":
		err = setup(ctx, args[1:])
	case "kubeconfig":
		err = runKubeconfig(ctx, args[1:])
	case "tunnel":
		err = runTunnel(ctx, args[1:])
	case "network":
		err = runNetwork(ctx, args[1:])
	case "nodes":
		err = runNodes(ctx, args[1:])
	case "vm":
		err = runVM(ctx, args[1:])
	case "status", "doctor":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		if err = fs.Parse(args[1:]); err == nil {
			if fs.NArg() != 0 {
				return errors.New("unexpected positional arguments")
			}
			var cfg Config
			if cfg, err = loadConfig(); err == nil {
				err = report(ctx, cfg, args[0] == "doctor", os.Stdout)
			}
		}
	case "containers", "logs", "kubectl":
		cfg, e := loadConfig()
		if e != nil {
			return e
		}
		forward := args[1:]
		humanContainers := args[0] == "containers" && !hasOutputFlags(forward)
		switch args[0] {
		case "containers":
			prefix := []string{"get", "pods"}
			if !hasOutputFormat(forward) {
				prefix = append(prefix, "-o", "wide")
			}
			if humanContainers {
				fmt.Fprintf(os.Stdout, "Workloads (Kubernetes pods) — hub %s\n", cfg.Hub)
			}
			if !hasNamespace(forward) {
				prefix = append(prefix, "--all-namespaces")
			}
			forward = append(prefix, forward...)
		case "logs":
			forward = append([]string{"logs"}, forward...)
		}
		err = remoteKube(ctx, cfg, forward, os.Stdin, os.Stdout, os.Stderr)
		if err == nil && humanContainers {
			fmt.Fprintln(os.Stdout, "\nNext: deepai-connect logs <POD> -n <NAMESPACE>")
		}
	default:
		return fmt.Errorf("unknown desktop command %q", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func requestsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func hasOutputFlags(args []string) bool {
	if hasOutputFormat(args) {
		return true
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--no-headers") || strings.HasPrefix(arg, "--template") || strings.HasPrefix(arg, "--raw") || arg == "-w" || strings.HasPrefix(arg, "-w=") || arg == "--watch" || strings.HasPrefix(arg, "--watch=") || strings.HasPrefix(arg, "--watch-only") {
			return true
		}
	}
	return false
}

func hasOutputFormat(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-o") && !strings.HasPrefix(arg, "--") || arg == "--output" || strings.HasPrefix(arg, "--output=") {
			return true
		}
	}
	return false
}

func hasNamespace(args []string) bool {
	for _, arg := range args {
		if (strings.HasPrefix(arg, "-n") && !strings.HasPrefix(arg, "--")) || arg == "--namespace" || strings.HasPrefix(arg, "--namespace=") || arg == "-A" || strings.HasPrefix(arg, "-A=") || arg == "--all-namespaces" || strings.HasPrefix(arg, "--all-namespaces=") {
			return true
		}
	}
	return false
}

var hubPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9.-]*$`)
var vmPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

func (cfg Config) validate(requireIP bool) error {
	if !hubPattern.MatchString(cfg.Hub) {
		return errors.New("hub must be USER@HOST with a hostname or IPv4 address")
	}
	if !path.IsAbs(cfg.StateDir) || path.Clean(cfg.StateDir) != cfg.StateDir || strings.ContainsAny(cfg.StateDir, "\x00\r\n") {
		return errors.New("hub state directory must be a clean absolute Linux path")
	}
	if cfg.VM != "" && !vmPattern.MatchString(cfg.VM) {
		return errors.New("VM name may contain only letters, numbers and hyphens")
	}
	if cfg.OverlayIP != "" || requireIP {
		ip, err := netip.ParseAddr(cfg.OverlayIP)
		if err != nil || !ip.Is4() || !netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			return errors.New("hub overlay address must be IPv4 within 100.64.0.0/10")
		}
	}
	return nil
}

func configPath() (string, error) {
	if p := os.Getenv("DEEPAI_CONNECT_CONFIG"); p != "" {
		return filepath.Abs(p)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "deepai-connect", "client.json"), nil
}

func loadConfig() (Config, error) {
	var cfg Config
	p, err := configPath()
	if err != nil {
		return cfg, err
	}
	data, err := platform.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, errNoHub
	}
	if err != nil {
		return cfg, fmt.Errorf("read client configuration: %w", err)
	}
	if err = json.Unmarshal(data, &cfg); err != nil {
		return cfg, errors.New("invalid client configuration")
	}
	return cfg, cfg.validate(true)
}

func saveConfig(cfg Config) error {
	if err := cfg.validate(true); err != nil {
		return err
	}
	p, err := configPath()
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(p); err == nil && !fi.Mode().IsRegular() {
		return errors.New("client configuration must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFile(p, append(data, '\n'), false)
}

func setup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: deepai-connect setup --hub USER@HOST [--vm NAME]\nSave SSH access to an installed hub; this does not join this computer to the mesh.\n\nExample: deepai-connect setup --hub root@hub.example\n")
		fs.PrintDefaults()
	}
	hub := fs.String("hub", "", "existing hub SSH destination, USER@HOST (root or passwordless sudo)")
	dir := fs.String("dir", defaultStateDir, "hub installation directory")
	vm := fs.String("vm", "", "existing local Multipass worker to include in health checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg := Config{Hub: *hub, StateDir: *dir, VM: *vm}
	if err := cfg.validate(false); err != nil {
		return err
	}
	// Re-running setup for the same hub keeps explicit preferences unless changed.
	if old, err := loadConfig(); err == nil && old.Hub == cfg.Hub {
		visited := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		if !visited["dir"] {
			cfg.StateDir = old.StateDir
		}
		if !visited["vm"] {
			cfg.VM = old.VM
		}
	}
	data, err := captureRemote(ctx, cfg, "/usr/local/bin/deepai-connect", "inspect", "--dir", cfg.StateDir)
	if err != nil {
		return fmt.Errorf("connect to hub (check SSH access, known_hosts and root/passwordless sudo): %w", err)
	}
	state, err := parseInspect(data)
	if err != nil {
		return err
	}
	cfg.OverlayIP = state.Address
	if err = cfg.validate(true); err != nil {
		return err
	}
	if err = saveConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("Configured SSH access to hub %s (%s).\n", cfg.Hub, cfg.OverlayIP)
	if _, err = captureKube(ctx, cfg, "get", "--raw=/readyz"); err != nil {
		fmt.Fprintln(os.Stderr, "WARN Kubernetes API is unavailable; hub access was saved.")
	}
	if cfg.VM != "" {
		if state, vmErr := vmState(ctx, cfg.VM); vmErr != nil || state != "Running" {
			fmt.Fprintf(os.Stderr, "WARN local VM %s is unavailable or not running; hub access was saved.\n", cfg.VM)
		}
	}
	fmt.Println("Run deepai-connect doctor to check health, or deepai-connect status for an overview.")
	return nil
}

func baseSSHArgs(cfg Config) []string {
	return []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-T", cfg.Hub}
}

func sshArgs(cfg Config, remoteArgs []string) ([]string, error) {
	if err := cfg.validate(false); err != nil {
		return nil, err
	}
	if len(remoteArgs) == 0 {
		return nil, errors.New("remote command is empty")
	}
	quoted := make([]string, len(remoteArgs))
	for i, arg := range remoteArgs {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return nil, errors.New("command arguments cannot contain NUL or line breaks")
		}
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return append(baseSSHArgs(cfg), strings.Join(quoted, " ")), nil
}

func privileged(cfg Config, args []string) []string {
	if strings.HasPrefix(cfg.Hub, "root@") {
		return args
	}
	return append([]string{"sudo", "-n", "--"}, args...)
}

func remote(ctx context.Context, cfg Config, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	ssh, err := sshArgs(cfg, privileged(cfg, args))
	if err != nil {
		return err
	}
	return runProcess(ctx, "ssh", ssh, stdin, stdout, stderr)
}

func captureRemote(ctx context.Context, cfg Config, args ...string) ([]byte, error) {
	var stdout bytes.Buffer
	if err := remote(ctx, cfg, args, nil, &stdout, io.Discard); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func remoteKube(ctx context.Context, cfg Config, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := cfg.validate(true); err != nil {
		return err
	}
	kube := []string{"/usr/local/bin/k3s", "kubectl", "--kubeconfig", path.Join(cfg.StateDir, "cluster", "kubeconfig"), "--server=https://" + cfg.OverlayIP + ":6443"}
	ssh, err := sshArgs(cfg, privileged(cfg, append(kube, args...)))
	if err != nil {
		return err
	}
	file, isFile := stdin.(*os.File)
	if kubeTTY(args, isFile && term.IsTerminal(int(file.Fd()))) {
		for i, arg := range ssh[:len(ssh)-2] {
			if arg == "-T" {
				ssh[i] = "-t"
			}
		}
	}
	return runProcess(ctx, "ssh", ssh, stdin, stdout, stderr)
}

func kubeTTY(args []string, terminal bool) bool {
	if !terminal {
		return false
	}
	interactive, tty := false, false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "exec" || arg == "attach" {
			interactive = true
		}
		switch arg {
		case "-t", "-it", "-ti", "--tty", "--tty=true", "-t=true":
			tty = true
		case "--tty=false", "-t=false":
			tty = false
		}
	}
	return interactive && tty
}

func captureKube(ctx context.Context, cfg Config, args ...string) ([]byte, error) {
	var stdout bytes.Buffer
	if err := remoteKube(ctx, cfg, append([]string{"--request-timeout=15s"}, args...), nil, &stdout, io.Discard); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}
