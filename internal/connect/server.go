package connect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"github.com/deepai-cloud/deepai-connect/internal/runtime/docker"
)

type State struct {
	ID, Domain, PublicIP, Email string
	Apps                        []string
	Token, CA, Certificate, Key string
	NetworkID                   string
	Containers                  map[string]string
	Configured                  map[string]bool
}

type Server struct {
	State
	Dir    string
	Docker docker.Client
}

func (s State) name(part string) string { return "deepai-connect-" + s.ID[:12] + "-" + part }
func (h *Server) save() error {
	return platform.WriteFile(filepath.Join(h.Dir, "connect.json"), encoded(h.State), false)
}

func load(dir string, d docker.Client) (*Server, error) {
	b, err := platform.ReadFile(filepath.Join(dir, "connect.json"))
	if err != nil {
		return nil, err
	}
	h := &Server{Dir: dir, Docker: d}
	if err = json.Unmarshal(b, &h.State); err != nil {
		return nil, errors.New("invalid server state; restore its private backup")
	}
	if err = validConfig(h.State); err != nil {
		return nil, err
	}
	if !secret(h.ID) || !secret(h.Token) || h.Containers == nil || h.Configured == nil {
		return nil, errors.New("incomplete server state")
	}
	pair, err := tls.X509KeyPair([]byte(h.Certificate), []byte(h.Key))
	if err != nil {
		return nil, errors.New("invalid server TLS identity")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid server TLS certificate")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(h.CA))
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: h.Domain}); err != nil {
		return nil, errors.New("server private TLS certificate is invalid or expired; restore or rotate its identity")
	}
	if h.NetworkID != "" && !secret(h.NetworkID) {
		return nil, errors.New("invalid saved server network identity")
	}
	for k, id := range h.Containers {
		if !slices.Contains([]string{"headscale", "frps", "caddy"}, k) || !secret(id) {
			return nil, errors.New("invalid saved server container identity")
		}
	}
	for k, configured := range h.Configured {
		if configured && h.Containers[k] == "" {
			return nil, errors.New("configured server service has no saved container identity")
		}
	}
	return h, nil
}

func checkFresh(ctx context.Context, d docker.Client) error {
	for _, args := range [][]string{{"container", "ls", "-a", "--filter", "label=" + label, "--format", "{{.ID}}"}, {"volume", "ls", "--filter", "label=" + label, "--format", "{{.Name}}"}, {"network", "ls", "--filter", "label=" + label, "--format", "{{.ID}}"}} {
		b, err := d.Run(ctx, nil, args...)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(b)) != 0 {
			return errors.New("existing server resources found; restore their private server state instead of creating another server")
		}
	}
	return nil
}

func (h *Server) verify(ctx context.Context) error {
	for _, service := range []string{"headscale", "frps", "caddy"} {
		c, err := h.Docker.Inspect(ctx, h.name(service))
		if err != nil {
			return err
		}
		id := h.Containers[service]
		if c == nil {
			if id != "" {
				return fmt.Errorf("saved %s container is missing; restore the server, do not recreate its identity", service)
			}
			continue
		}
		image := map[string]string{"headscale": HeadscaleImage, "frps": FRPSImage, "caddy": CaddyImage}[service]
		if c.Config.Labels[label] != h.ID || c.Config.Labels[label+".service"] != service || c.HostConfig.NetworkMode != h.name("network") || c.Config.Image != image || id != "" && c.ID != id {
			return fmt.Errorf("%s container identity conflicts with server state", service)
		}
		if id == "" && c.State.Running {
			return errors.New("unrecorded running server container; refusing to adopt it")
		}
	}
	return nil
}

func (h *Server) resource(ctx context.Context, kind, part string) (string, error) {
	name := h.name(part)
	b, err := h.Docker.Run(ctx, nil, kind, "ls", "--filter", "name=^"+name+"$", "--format", "{{.Name}}")
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		if kind == "network" && h.NetworkID != "" {
			return "", errors.New("saved server network is missing")
		}
		args := []string{kind, "create", "--label", label + "=" + h.ID}
		if kind == "network" {
			args = append(args, "--driver", "bridge")
		}
		if _, err = h.Docker.Run(ctx, nil, append(args, name)...); err != nil {
			return "", err
		}
	}
	var resources []struct {
		ID     string `json:"Id"`
		Name   string
		Labels map[string]string
	}
	if err = h.Docker.JSON(ctx, &resources, kind, "inspect", name); err != nil {
		return "", err
	}
	if len(resources) != 1 || resources[0].Labels[label] != h.ID {
		return "", fmt.Errorf("foreign server %s; refusing to use it", kind)
	}
	if kind == "network" && h.NetworkID != "" && resources[0].ID != h.NetworkID {
		return "", errors.New("server network identity changed")
	}
	return resources[0].ID, nil
}

func (h *Server) up(ctx context.Context) error {
	if err := h.verify(ctx); err != nil {
		return err
	}
	id, err := h.resource(ctx, "network", "network")
	if err != nil {
		return err
	}
	h.NetworkID = id
	if err = h.save(); err != nil {
		return err
	}
	for _, service := range []string{"headscale", "frps", "caddy"} {
		if err = h.ensure(ctx, service); err != nil {
			return fmt.Errorf("%s: %w", service, err)
		}
	}
	ready, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		if _, err = h.headscale(ready, "users", "list"); err == nil {
			for _, service := range []string{"headscale", "frps", "caddy"} {
				c, e := h.Docker.Inspect(ready, h.name(service))
				if e != nil {
					return e
				}
				if c == nil || !c.State.Running {
					return fmt.Errorf("%s is not running; inspect its logs and resume deepai-connect up", service)
				}
			}
			return nil
		}
		select {
		case <-ready.Done():
			return errors.New("server containers started but Headscale is not ready; inspect their logs and rerun deepai-connect up")
		case <-time.After(time.Second):
		}
	}
}

func (h *Server) ensure(ctx context.Context, service string) error {
	image := map[string]string{"headscale": HeadscaleImage, "frps": FRPSImage, "caddy": CaddyImage}[service]
	volumes := map[string]map[string]string{"headscale": {"headscale-data": "/var/lib/headscale", "headscale-config": "/etc/headscale"}, "frps": {"frps-config": "/etc/deepai"}, "caddy": {"caddy-data": "/data", "caddy-config": "/config"}}[service]
	args := []string{"create", "--name", h.name(service), "--label", label + "=" + h.ID, "--label", label + ".service=" + service, "--network", h.name("network"), "--restart", "unless-stopped", "--user", "0:0", "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--log-opt", "max-size=10m", "--log-opt", "max-file=3"}
	for part, path := range volumes {
		if _, err := h.resource(ctx, "volume", part); err != nil {
			return err
		}
		args = append(args, "--mount", "type=volume,src="+h.name(part)+",dst="+path+",volume-nocopy")
	}
	files := map[string][]byte{}
	switch service {
	case "headscale":
		args = append(args, "-p", "3478:3478/udp", "--entrypoint", "/ko-app/headscale", image, "serve", "--config", "/etc/headscale/config.json")
		files["etc/headscale/config.json"] = headscaleConfig(h.State)
		files["etc/headscale/policy.json"] = []byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"randomizeClientPort":true}`)
	case "frps":
		args = append(args, "-p", "7000:7000/tcp", image, "-c", "/etc/deepai/frps.json")
		files["etc/deepai/frps.json"], files["etc/deepai/server.crt"], files["etc/deepai/server.key"] = frpsConfig(h.State), []byte(h.Certificate), []byte(h.Key)
	case "caddy":
		args = append(args, "--cap-add", "NET_BIND_SERVICE", "-p", "80:80/tcp", "-p", "443:443/tcp", image, "caddy", "run", "--config", "/config/caddy.json")
		files["config/caddy.json"] = caddyConfig(h.State)
	}
	c, err := h.Docker.Inspect(ctx, h.name(service))
	if err != nil {
		return err
	}
	if c == nil {
		b, err := h.Docker.Run(ctx, nil, args...)
		if err != nil {
			return err
		}
		h.Containers[service] = strings.TrimSpace(string(b))
		if !secret(h.Containers[service]) {
			return errors.New("invalid Docker create identity")
		}
		if err = h.save(); err != nil {
			return err
		}
	} else if h.Containers[service] == "" {
		h.Containers[service] = c.ID
		if err = h.save(); err != nil {
			return err
		}
	}
	if !h.Configured[service] {
		if c != nil && c.State.Running {
			return errors.New("unconfigured container is running; refusing to replace its configuration")
		}
		if err = h.Docker.CopyFiles(ctx, h.Containers[service], "/", files); err != nil {
			return err
		}
		h.Configured[service] = true
		if err = h.save(); err != nil {
			return err
		}
	}
	if c == nil || !c.State.Running {
		_, err = h.Docker.Run(ctx, nil, "start", h.Containers[service])
	}
	if err == nil {
		var check []string
		switch service {
		case "frps":
			check = []string{"/usr/bin/frps", "verify", "-c", "/etc/deepai/frps.json"}
		case "caddy":
			check = []string{"caddy", "validate", "--config", "/config/caddy.json"}
		}
		if len(check) > 0 {
			_, err = h.Docker.Run(ctx, nil, append([]string{"exec", h.Containers[service]}, check...)...)
		}
	}
	return err
}

func (h *Server) headscale(ctx context.Context, args ...string) ([]byte, error) {
	return h.Docker.Run(ctx, nil, append([]string{"exec", h.Containers["headscale"], "/ko-app/headscale", "--config", "/etc/headscale/config.json", "--output", "json"}, args...)...)
}

func (h *Server) invite(ctx context.Context, out string) error {
	if _, err := os.Lstat(out); err == nil {
		return errors.New("credential output already exists; choose a new path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := h.headscale(ctx, "users", "list", "--name", "owner")
	if err != nil {
		return err
	}
	var users []struct {
		ID   json.RawMessage `json:"id"`
		Name string          `json:"name"`
	}
	if err = json.Unmarshal(b, &users); err != nil {
		return errors.New("invalid Headscale user response")
	}
	if len(users) == 0 {
		if _, err = h.headscale(ctx, "users", "create", "owner"); err != nil {
			return err
		}
		b, err = h.headscale(ctx, "users", "list", "--name", "owner")
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &users); err != nil {
			return errors.New("invalid Headscale user response")
		}
	}
	if len(users) != 1 || users[0].Name != "owner" {
		return errors.New("ambiguous Headscale owner")
	}
	id := strings.Trim(string(users[0].ID), `"`)
	if n, err := strconv.ParseUint(id, 10, 64); err != nil || n == 0 {
		return errors.New("invalid Headscale owner ID")
	}
	b, err = h.headscale(ctx, "preauthkeys", "create", "--user", id, "--expiration", "1h")
	if err != nil {
		return err
	}
	var key struct {
		Key string `json:"key"`
	}
	if err = json.Unmarshal(b, &key); err != nil || len(key.Key) < 32 || strings.ContainsAny(key.Key, "\r\n\x00") {
		return errors.New("invalid Headscale enrollment key response")
	}
	return platform.WriteFile(out, []byte(key.Key+"\n"), true)
}
