package connect

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"

	"github.com/deepai-cloud/deepai-connect/internal/contract/edgeaccess"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

type accessOptions struct {
	Format, Domain, LocalIP string
	LocalPort               int
}

type bundleFile struct {
	name string
	data []byte
}

func (o accessOptions) validate() error {
	if o.Format == "profile" {
		return nil
	}
	if o.Format != "frpc" {
		return errors.New("access format must be profile or frpc")
	}
	if !edgeaccess.ValidDomain(o.Domain) {
		return errors.New("FRPC export requires --domain with a configured application hostname")
	}
	ip := net.ParseIP(o.LocalIP)
	if ip == nil || (!ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
		return errors.New("--local-ip must be a numeric unicast IPv4 or IPv6 address")
	}
	if o.LocalPort < 1 || o.LocalPort > 65535 {
		return errors.New("--local-port must be between 1 and 65535")
	}
	return nil
}

func (h *Server) exportAccess(out string, o accessOptions) error {
	if err := o.validate(); err != nil {
		return err
	}
	if out == "" {
		return errors.New("access requires --out")
	}
	if len(h.Apps) == 0 {
		return errors.New("this server has no configured application domains")
	}
	profile := edgeaccess.Profile{Version: 1, Server: h.Domain, Port: 7000, Token: h.Token, CA: h.CA, Domains: h.Apps}
	if err := profile.Validate(); err != nil {
		return err
	}
	if o.Format == "profile" {
		return platform.WriteFile(out, encoded(profile), true)
	}
	if !slices.Contains(h.Apps, o.Domain) {
		return errors.New("--domain is not a configured application hostname on this server")
	}
	// FRPC v0.71.0 resolves these relative file paths from its working directory.
	// Keep the bearer secret in its own file and leave the admin listener disabled.
	config := encoded(map[string]any{
		"serverAddr": h.Domain, "serverPort": 7000, "loginFailExit": true,
		"auth": map[string]any{"method": "token", "additionalScopes": []string{"HeartBeats", "NewWorkConns"},
			"tokenSource": map[string]any{"type": "file", "file": map[string]string{"path": "./token"}}},
		"transport": map[string]any{"tls": map[string]any{"enable": true, "trustedCaFile": "./ca.pem", "serverName": h.Domain}},
		"log":       map[string]string{"to": "console", "level": "warn"},
		"proxies": []any{map[string]any{"name": o.Domain, "type": "http", "customDomains": []string{o.Domain},
			"localIP": net.ParseIP(o.LocalIP).String(), "localPort": o.LocalPort}},
	})
	return writeClientBundle(out, []bundleFile{{"ca.pem", []byte(h.CA)}, {"token", []byte(h.Token)}, {"frpc.json", config}})
}

// Reserve a new directory before writing credentials. Failed exports remain
// private and are reported for manual removal; existing output is never adopted.
func writeClientBundle(out string, files []bundleFile) (result error) {
	out, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := platform.CheckPath(out); err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(out))
	if err != nil {
		return fmt.Errorf("open output parent directory: %w", err)
	}
	defer parent.Close()
	if err := parent.Mkdir(filepath.Base(out), 0700); err != nil {
		return fmt.Errorf("create new FRPC bundle directory: %w", err)
	}
	defer func() {
		if result != nil {
			result = fmt.Errorf("FRPC export failed; private partial output may remain at %s; remove it before retrying or choose a new path: %w", out, result)
		}
	}()
	if err := platform.SecureDir(out); err != nil {
		return err
	}
	for _, file := range files {
		if err := platform.WriteFile(filepath.Join(out, file.name), file.data, true); err != nil {
			return err
		}
	}
	return nil
}
