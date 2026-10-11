// Package connect owns the Linux VPS connectivity and HTTPS edge services.
package connect

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/deepai-cloud/deepai-connect/internal/buildinfo"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"github.com/deepai-cloud/deepai-connect/internal/runtime/docker"
)

const usage = `Usage: deepai-connect COMMAND [flags]

  up --domain NAME --public-ip IP --email EMAIL [--apps DOMAIN,...]
  up                         Resume saved server state
  status                     Inspect server services
  invite --out FILE          Issue a one-use mesh registration key
  access --out FILE          Export a private publishing profile
  access --format frpc --out DIRECTORY --domain NAME
                             Export a standalone FRPC client bundle
  version

Run on a Linux VPS. Use COMMAND --help for options; --dir PATH selects
private server state (default: deepai/connect in the OS config directory).
Docker keeps the services running after this command exits.
`

// Run is the native command boundary for server operations.
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Print(usage)
		return nil
	}
	if args[0] == "version" {
		fmt.Println(buildinfo.Version)
		return nil
	}
	command := args[0]
	if !slices.Contains([]string{"up", "status", "invite", "access"}, command) {
		return errors.New("unknown server command")
	}
	defaults, err := platform.DefaultDir()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("deepai-connect "+command, flag.ContinueOnError)
	var cfg State
	var apps, out string
	var access accessOptions
	dir := fs.String("dir", defaults, "private server state directory")
	fs.StringVar(&out, "out", "", "new private credential file or FRPC bundle directory")
	fs.StringVar(&cfg.Domain, "domain", "", "mesh hostname (up) or application hostname (access --format frpc)")
	fs.StringVar(&access.Format, "format", "profile", "access export format: profile or frpc")
	fs.StringVar(&access.LocalIP, "local-ip", "127.0.0.1", "HTTP backend IP address for access --format frpc")
	fs.IntVar(&access.LocalPort, "local-port", 8080, "HTTP backend port for access --format frpc")
	fs.StringVar(&cfg.PublicIP, "public-ip", "", "public VPS IPv4 address")
	fs.StringVar(&cfg.Email, "email", "", "ACME contact email")
	fs.StringVar(&apps, "apps", "", "comma-separated explicit public app hostnames")
	install := fs.Bool("install", true, "install Docker if missing")
	if err = fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected server arguments")
	}
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for name := range seen {
		allowed := name == "dir"
		switch command {
		case "up":
			allowed = allowed || slices.Contains([]string{"domain", "public-ip", "email", "apps", "install"}, name)
		case "invite":
			allowed = allowed || name == "out"
		case "access":
			allowed = allowed || name == "out" || name == "format" ||
				access.Format == "frpc" && slices.Contains([]string{"domain", "local-ip", "local-port"}, name)
		}
		if !allowed {
			return fmt.Errorf("--%s is not valid for deepai-connect %s; use --help for options", name, command)
		}
	}
	if (command == "invite" || command == "access") != (out != "") {
		return errors.New("deepai-connect invite/access require --out; up/status do not accept it")
	}
	if command == "access" {
		access.Domain = cfg.Domain
		if err := access.validate(); err != nil {
			return err
		}
	}
	if apps != "" {
		cfg.Apps = strings.Split(apps, ",")
		slices.Sort(cfg.Apps)
	}
	if command == "up" && runtime.GOOS != "linux" {
		return errors.New("run deepai-connect up on your public Linux VPS")
	}
	if command == "up" {
		release, err := platform.Lock(filepath.Join(defaults, ".runtime"))
		if err != nil {
			return err
		}
		defer release()
	}
	unlock, err := platform.Lock(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	h, err := load(*dir, docker.Client{})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if h == nil {
		if command != "up" {
			return errors.New("no server state; run deepai-connect up with --domain, --public-ip and --email")
		}
		if err = validConfig(cfg); err != nil {
			return err
		}
	} else if command == "up" {
		for key, pair := range map[string][2]string{"domain": {cfg.Domain, h.Domain}, "public-ip": {cfg.PublicIP, h.PublicIP}, "email": {cfg.Email, h.Email}, "apps": {strings.Join(cfg.Apps, ","), strings.Join(h.Apps, ",")}} {
			if seen[key] && pair[0] != pair[1] {
				return fmt.Errorf("--%s conflicts with the existing server; resume with plain deepai-connect up", key)
			}
		}
	}
	if command == "up" {
		if err = platform.EnsureDocker(ctx, *install); err != nil {
			return err
		}
	}
	d := docker.Client{Run: docker.Run}
	info, err := d.Check(ctx)
	if err != nil {
		return err
	}
	d = docker.Client{Run: docker.LocalRunner(info.Endpoint), Endpoint: info.Endpoint}
	if h == nil {
		if err = checkFresh(ctx, d); err != nil {
			return err
		}
		cfg.ID, cfg.Token = random(), random()
		cfg.Containers, cfg.Configured = map[string]string{}, map[string]bool{}
		cfg.CA, cfg.Certificate, cfg.Key, err = certificates(cfg.Domain)
		if err != nil {
			return err
		}
		h = &Server{State: cfg, Dir: *dir, Docker: d}
		if err = h.save(); err != nil {
			return err
		}
	}
	h.Docker = d
	if command == "up" {
		if err = h.up(ctx); err != nil {
			return err
		}
		fmt.Printf("DeepAI Connect containers are running for https://%s. Point its DNS and each app hostname to %s; allow TCP80/443/7000 and UDP3478 in the VPS firewall. Verify public HTTPS before enrolling devices.\n", h.Domain, h.PublicIP)
		return nil
	}
	if err = h.verify(ctx); err != nil {
		return err
	}
	switch command {
	case "status":
		for _, service := range []string{"headscale", "frps", "caddy"} {
			c, e := d.Inspect(ctx, h.name(service))
			if e != nil {
				return e
			}
			if c == nil {
				return fmt.Errorf("%s has not been created; resume deepai-connect up", service)
			}
			fmt.Printf("%s: %s\n", service, c.State.Status)
		}
		fmt.Println("Container state does not confirm DNS, public TLS, NAT traversal, or offsite recovery.")
	case "access":
		if err = h.exportAccess(out, access); err != nil {
			return err
		}
		if access.Format == "frpc" {
			fmt.Println("Private FRPC bundle saved. On the application host, run frpc -c ./frpc.json from inside the bundle directory.")
		} else {
			fmt.Println("Private application publishing profile saved; share only with hosts you own and trust.")
		}
	case "invite":
		if err = h.invite(ctx, out); err != nil {
			return err
		}
		fmt.Printf("One-use mesh enrollment key saved to %s; expires in one hour. Login server: https://%s\n", out, h.Domain)
	}
	return nil
}
