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
	"strings"

	"golang.org/x/term"
)

const defaultStateDir = "/var/lib/deepai-connect"

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

func Handles(command string) bool {
	switch command {
	case "setup", "status", "doctor", "nodes", "containers", "logs", "kubectl", "kubeconfig", "tunnel":
		return true
	}
	return false
}

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("a desktop administration command is required")
	}
	var err error
	switch args[0] {
	case "setup":
		err = setup(ctx, args[1:])
	case "kubeconfig":
		err = runKubeconfig(ctx, args[1:])
	case "tunnel":
		err = runTunnel(ctx, args[1:])
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
	case "nodes", "containers", "logs", "kubectl":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			usage := map[string]string{
				"nodes":      "nodes [kubectl get flags]",
				"containers": "containers [-n NAMESPACE] [kubectl get flags]",
				"logs":       "logs POD [-n NAMESPACE] [-c CONTAINER] [-f] [kubectl logs flags]",
				"kubectl":    "kubectl [kubectl arguments]",
			}
			fmt.Printf("Usage: deepai-connect %s\nUses the hub saved by deepai-connect setup; kubectl runs over SSH.\n", usage[args[0]])
			return nil
		}
		cfg, e := loadConfig()
		if e != nil {
			return e
		}
		forward := args[1:]
		switch args[0] {
		case "nodes":
			forward = append([]string{"get", "nodes"}, forward...)
		case "containers":
			prefix := []string{"get", "pods", "-o", "wide"}
			if !hasNamespace(forward) {
				prefix = append(prefix, "--all-namespaces")
			}
			forward = append(prefix, forward...)
		case "logs":
			forward = append([]string{"logs"}, forward...)
		}
		err = remoteKube(ctx, cfg, forward, os.Stdin, os.Stdout, os.Stderr)
	default:
		return fmt.Errorf("unknown desktop command %q", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func hasNamespace(args []string) bool {
	for _, arg := range args {
		if arg == "-n" || strings.HasPrefix(arg, "-n=") || (strings.HasPrefix(arg, "-n") && !strings.HasPrefix(arg, "--")) || arg == "--namespace" || strings.HasPrefix(arg, "--namespace=") || arg == "-A" || strings.HasPrefix(arg, "-A=") || arg == "--all-namespaces" || strings.HasPrefix(arg, "--all-namespaces=") {
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
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, errors.New("no hub configured; run deepai-connect setup --hub USER@HOST")
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
	if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".client-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

func setup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
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
	if _, err = captureKube(ctx, cfg, "get", "--raw=/readyz"); err != nil {
		return fmt.Errorf("hub Kubernetes API is unavailable; configuration was not changed: %w", err)
	}
	if cfg.VM != "" {
		if _, err = vmState(ctx, cfg.VM); err != nil {
			return fmt.Errorf("inspect local VM; configuration was not changed: %w", err)
		}
	}
	if err = saveConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("Configured hub %s (%s).\nRun deepai-connect status or deepai-connect containers.\n", cfg.Hub, cfg.OverlayIP)
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
