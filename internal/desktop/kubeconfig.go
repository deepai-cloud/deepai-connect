package desktop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultTunnelPort = 16443

type kubeDocument map[string]any

func runKubeconfig(ctx context.Context, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("Usage: deepai-connect kubeconfig export --out FILE | install [--out FILE] [--set-current] [--context NAME] [--direct]")
		return nil
	}
	if len(args) == 0 || (args[0] != "export" && args[0] != "install") {
		return errors.New("usage: deepai-connect kubeconfig export --out FILE | install [--out FILE] [--set-current] [--context NAME] [--direct]")
	}
	fs := flag.NewFlagSet("kubeconfig "+args[0], flag.ContinueOnError)
	out := fs.String("out", "", "destination file (install defaults to KUBECONFIG or ~/.kube/config)")
	name := fs.String("context", "deepai-connect", "name for the cluster, credentials and context")
	direct := fs.Bool("direct", false, "use the private mesh address; requires working local mesh access")
	port := fs.Int("port", defaultTunnelPort, "local port used by deepai-connect tunnel")
	setCurrent := fs.Bool("set-current", false, "select the installed context")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *name == "" || strings.TrimSpace(*name) != *name || strings.ContainsAny(*name, "\r\n\t") {
		return errors.New("provide flags only and a nonempty context name without surrounding whitespace")
	}
	if err := validateTunnelPort(*port); err != nil {
		return err
	}
	if args[0] == "export" && (*out == "" || *setCurrent) {
		return errors.New("kubeconfig export requires --out FILE; --set-current applies only to install")
	}
	if *direct && *port != defaultTunnelPort {
		return errors.New("--port applies to tunnel access, not --direct")
	}
	path, err := kubeconfigPath(*out)
	if err != nil {
		return err
	}
	previous, exists, err := readKubeconfigFile(path)
	if err != nil {
		return err
	}
	if args[0] == "export" && exists {
		return fmt.Errorf("destination %s already exists; choose a new file or use kubeconfig install to merge", path)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := validateOverlayIP(cfg.OverlayIP); err != nil {
		return err
	}
	if *direct {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.OverlayIP, "6443"))
		if err != nil {
			return errors.New("the hub's private Kubernetes API is unreachable from this host; omit --direct and run deepai-connect tunnel")
		}
		conn.Close()
	}
	raw, err := captureKube(ctx, cfg, "config", "view", "--flatten", "--raw", "--minify", "-o", "json")
	if err != nil {
		return errors.New("could not read hub kubeconfig over SSH; check deepai-connect doctor")
	}
	remote, err := decodeKubeconfig(raw)
	if err != nil {
		return errors.New("hub returned an invalid kubeconfig")
	}
	managed, err := desktopKubeconfig(remote, cfg, *name, *port, *direct)
	if err != nil {
		return err
	}
	result := managed
	if args[0] == "install" && exists && len(bytes.TrimSpace(previous)) != 0 {
		// kubectl resolves relative certificate/key paths before our merge. Config
		// view does not contact the API or execute credential plugins.
		var stdout bytes.Buffer
		if err := runProcess(ctx, "kubectl", []string{"--kubeconfig", path, "config", "view", "--flatten", "--raw", "-o", "json"}, nil, &stdout, io.Discard); err != nil {
			return errors.New("could not read existing kubeconfig; install kubectl and check the file is valid (destination unchanged)")
		}
		existing, err := decodeKubeconfig(stdout.Bytes())
		if err != nil {
			return errors.New("existing kubeconfig is invalid (destination unchanged)")
		}
		result, err = mergeKubeconfig(existing, managed, *name, *setCurrent)
		if err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errors.New("could not encode kubeconfig")
	}
	if err := writeKubeconfigFile(path, append(data, '\n'), previous, exists); err != nil {
		return err
	}
	fmt.Printf("Kubeconfig %s: %s (context %s)\n", args[0], path, *name)
	if !*direct {
		fmt.Printf("Run deepai-connect tunnel --port %d while using this context.\n", *port)
	}
	return nil
}

func kubeconfigPath(out string) (string, error) {
	if out == "" {
		var paths []string
		for _, path := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
			if path != "" {
				paths = append(paths, path)
			}
		}
		if len(paths) > 1 {
			return "", errors.New("KUBECONFIG contains multiple files; specify --out FILE to choose which file to update")
		}
		if len(paths) == 1 {
			out = paths[0]
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			out = filepath.Join(home, ".kube", "config")
		}
	}
	if out == "-" {
		return "", errors.New("use a file path for --out; kubeconfig contains administrator credentials")
	}
	return filepath.Abs(out)
}

func decodeKubeconfig(data []byte) (kubeDocument, error) {
	var doc kubeDocument
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil || doc["apiVersion"] != "v1" || doc["kind"] != "Config" {
		return nil, errors.New("invalid kubeconfig")
	}
	for _, key := range []string{"clusters", "users", "contexts"} {
		if _, err := kubeEntries(doc, key); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func kubeEntries(doc kubeDocument, key string) ([]any, error) {
	if doc[key] == nil {
		return nil, nil
	}
	entries, ok := doc[key].([]any)
	if !ok {
		return nil, errors.New("invalid kubeconfig entries")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		item, ok := entry.(map[string]any)
		name, _ := item["name"].(string)
		if !ok || name == "" || seen[name] {
			return nil, errors.New("invalid or duplicate kubeconfig names")
		}
		seen[name] = true
	}
	return entries, nil
}

func desktopKubeconfig(remote kubeDocument, cfg Config, name string, port int, direct bool) (kubeDocument, error) {
	sections := map[string]map[string]any{}
	names := map[string]string{}
	for key, inner := range map[string]string{"clusters": "cluster", "users": "user", "contexts": "context"} {
		entries, err := kubeEntries(remote, key)
		if err != nil || len(entries) != 1 {
			return nil, errors.New("hub kubeconfig must contain exactly one cluster, user and context")
		}
		item := entries[0].(map[string]any)
		body, ok := item[inner].(map[string]any)
		if !ok {
			return nil, errors.New("hub kubeconfig has an invalid entry")
		}
		sections[inner], names[inner] = body, item["name"].(string)
	}
	cluster, user, current := sections["cluster"], sections["user"], sections["context"]
	if current["cluster"] != names["cluster"] || current["user"] != names["user"] || remote["current-context"] != names["context"] {
		return nil, errors.New("hub kubeconfig context does not match its credentials")
	}
	// Export only embedded K3s certificate credentials, never insecure TLS,
	// host-local file references, proxy settings or executable auth plugins.
	if insecure, _ := cluster["insecure-skip-tls-verify"].(bool); insecure {
		return nil, errors.New("refusing hub kubeconfig with TLS verification disabled")
	}
	for _, pair := range []struct {
		body map[string]any
		key  string
	}{{cluster, "certificate-authority-data"}, {user, "client-certificate-data"}, {user, "client-key-data"}} {
		value, ok := pair.body[pair.key].(string)
		decoded, err := base64.StdEncoding.DecodeString(value)
		if !ok || err != nil || len(decoded) == 0 {
			return nil, errors.New("hub kubeconfig must use embedded CA, client certificate and client key data")
		}
	}
	server := "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if direct {
		server = "https://" + net.JoinHostPort(cfg.OverlayIP, "6443")
	}
	marker := []any{map[string]any{"name": "deepai-connect", "extension": map[string]any{"managed-by": "deepai-connect", "hub": cfg.Hub, "overlay-ip": cfg.OverlayIP}}}
	return kubeDocument{
		"apiVersion": "v1", "kind": "Config", "preferences": map[string]any{}, "current-context": name,
		"clusters": []any{map[string]any{"name": name, "cluster": map[string]any{"server": server, "tls-server-name": cfg.OverlayIP, "certificate-authority-data": cluster["certificate-authority-data"], "extensions": marker}}},
		"users":    []any{map[string]any{"name": name, "user": map[string]any{"client-certificate-data": user["client-certificate-data"], "client-key-data": user["client-key-data"], "extensions": marker}}},
		"contexts": []any{map[string]any{"name": name, "context": map[string]any{"cluster": name, "user": name, "extensions": marker}}},
	}, nil
}

func mergeKubeconfig(existing, managed kubeDocument, name string, setCurrent bool) (kubeDocument, error) {
	result := make(kubeDocument, len(existing))
	for key, value := range existing {
		result[key] = value
	}
	for key, inner := range map[string]string{"clusters": "cluster", "users": "user", "contexts": "context"} {
		entries, err := kubeEntries(existing, key)
		if err != nil {
			return nil, err
		}
		entries = append([]any(nil), entries...)
		addition := managed[key].([]any)[0].(map[string]any)
		found := false
		for i, entry := range entries {
			item := entry.(map[string]any)
			if item["name"] != name {
				continue
			}
			old, _ := item[inner].(map[string]any)
			fresh := addition[inner].(map[string]any)
			if !sameKubeOwner(old, fresh) {
				return nil, fmt.Errorf("kubeconfig name %q already exists in %s; choose a different --context (destination unchanged)", name, key)
			}
			if key == "contexts" {
				// Retain the user's namespace and other context preferences.
				body := make(map[string]any, len(old))
				for k, v := range old {
					body[k] = v
				}
				for k, v := range fresh {
					body[k] = v
				}
				addition = map[string]any{"name": name, inner: body}
			}
			// Other contexts may reference the managed cluster and user. Keep
			// those references valid while refreshing our own credentials.
			entries[i], found = addition, true
		}
		if !found {
			entries = append(entries, addition)
		}
		result[key] = entries
	}
	if setCurrent {
		result["current-context"] = name
	}
	return result, nil
}

func sameKubeOwner(a, b map[string]any) bool {
	owner := func(body map[string]any) map[string]any {
		extensions, _ := body["extensions"].([]any)
		for _, raw := range extensions {
			ext, _ := raw.(map[string]any)
			if ext["name"] == "deepai-connect" {
				value, _ := ext["extension"].(map[string]any)
				return value
			}
		}
		return nil
	}
	x, y := owner(a), owner(b)
	return x != nil && y != nil && x["managed-by"] == "deepai-connect" && x["hub"] == y["hub"] && x["overlay-ip"] == y["overlay-ip"]
}

func readKubeconfigFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("kubeconfig destination must be a regular file; for a symlink, pass its resolved target with --out")
	}
	data, err := os.ReadFile(path)
	return data, true, err
}

func writeKubeconfigFile(path string, data, previous []byte, existed bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".deepai-kubeconfig-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now, exists, err := readKubeconfigFile(path)
	if err != nil {
		return err
	}
	if exists != existed || !bytes.Equal(previous, now) {
		return errors.New("kubeconfig changed during installation; retry (destination unchanged)")
	}
	return os.Rename(f.Name(), path)
}

func validateOverlayIP(value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil || !netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
		return errors.New("hub mesh IP must be within 100.64.0.0/10; refresh configuration with deepai-connect setup --hub USER@HOST")
	}
	return nil
}

func validateTunnelPort(port int) error {
	if port < 1024 || port > 65535 {
		return errors.New("--port must be between 1024 and 65535")
	}
	return nil
}

func tunnelArgs(cfg Config, port int) ([]string, error) {
	if err := validateOverlayIP(cfg.OverlayIP); err != nil {
		return nil, err
	}
	if err := validateTunnelPort(port); err != nil {
		return nil, err
	}
	forward := "127.0.0.1:" + strconv.Itoa(port) + ":" + cfg.OverlayIP + ":6443"
	args := []string{"-N", "-L", forward, "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"}
	return append(args, baseSSHArgs(cfg)...), nil
}

func runTunnel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	port := fs.Int("port", defaultTunnelPort, "loopback port for Kubernetes access")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("tunnel accepts flags only")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ssh, err := tunnelArgs(cfg, *port)
	if err != nil {
		return err
	}
	fmt.Printf("Opening Kubernetes tunnel at https://127.0.0.1:%d; leave this command running (Ctrl-C to stop).\n", *port)
	return runProcess(ctx, "ssh", ssh, nil, os.Stdout, os.Stderr)
}
