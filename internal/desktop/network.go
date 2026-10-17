package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

const networkHelp = `Usage: deepai-connect network [--local] [--dir PATH] [--json]

See device IPs, discovered paths and tunnel latency from the saved hub.
Without a saved hub, Linux uses its local agent. macOS and Windows need setup.

  --local     Check this Linux host instead of the saved hub
  --dir PATH  Local installation directory (default: /var/lib/deepai-connect)
  --json      Print a structured report

Examples:
  deepai-connect network
  deepai-connect network --local

For problems and next steps: deepai-connect doctor
`

const networkUpgrade = "network diagnostics unavailable; upgrade the hub binary and restart its host agent"

func runNetwork(ctx context.Context, args []string) error {
	return networkCommand(ctx, args, runtime.GOOS, os.Stdout)
}

func networkCommand(ctx context.Context, args []string, goos string, out io.Writer) error {
	fs := flag.NewFlagSet("network", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), networkHelp) }
	local := fs.Bool("local", false, "check this Linux host")
	dir := fs.String("dir", defaultStateDir, "local installation directory")
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
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		// Preserve JSON errors even if an invalid flag appeared before --json.
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
		return fail(err)
	}
	if fs.NArg() != 0 {
		return fail(errors.New("unexpected arguments; run deepai-connect help network"))
	}
	dirSet := false
	fs.Visit(func(f *flag.Flag) { dirSet = dirSet || f.Name == "dir" })
	cfg, err := networkTarget(goos, *local, dirSet)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var report *hostnet.NetworkReport
	if cfg != nil {
		report, err = remoteNetwork(ctx, *cfg)
	} else {
		report, err = hostnet.Network(ctx, filepath.Join(*dir, "network"))
		if errors.Is(err, hostnet.ErrNetworkUnsupported) {
			err = errors.New("network diagnostics unavailable; upgrade this host's binary and restart its host agent")
		} else if err != nil {
			err = fmt.Errorf("local host agent unavailable: %w", err)
		}
	}
	if err != nil {
		return fail(err)
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(report)
	}
	printNetwork(out, report, cfg)
	return nil
}

// An absent configuration permits local Linux use. Broken configuration or
// failed hub access must never silently change the observation source.
func networkTarget(goos string, local, dirSet bool) (*Config, error) {
	if !local {
		p, err := configPath()
		if err != nil {
			return nil, err
		}
		if _, err = os.Lstat(p); err == nil {
			cfg, err := loadConfig()
			if err != nil {
				return nil, err
			}
			if dirSet {
				return nil, errors.New("--dir applies only with --local; hub commands use the directory saved by setup")
			}
			return &cfg, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read client configuration: %w", err)
		}
	}
	if goos != "linux" {
		return nil, errors.New("local network inspection requires Linux; run deepai-connect setup --hub USER@HOST to inspect your hub")
	}
	return nil, nil
}

func remoteNetwork(ctx context.Context, cfg Config) (*hostnet.NetworkReport, error) {
	var stdout, stderr bytes.Buffer
	err := remote(ctx, cfg, []string{"/usr/local/bin/deepai-connect", "network", "--local", "--dir", cfg.StateDir, "--json"}, nil, &stdout, &stderr)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("network check on %s: %w", cfg.Hub, ctx.Err())
	}
	// This exact diagnostic is emitted by the previous CLI. SSH, socket and
	// arbitrary command failures are not evidence of an unsupported version.
	if err != nil && strings.TrimSpace(stderr.String()) == `deepai-connect: unknown command "network"; run deepai-connect --help` {
		return nil, errors.New(networkUpgrade)
	}
	var report hostnet.NetworkReport
	decodeErr := json.Unmarshal(stdout.Bytes(), &report)
	if decodeErr == nil && report.SchemaVersion == 1 && !report.Source.IP.IsValid() && report.Error != "" {
		return nil, fmt.Errorf("hub network check: %s", report.Error)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot inspect network on %s over SSH: %w", cfg.Hub, err)
	}
	if decodeErr != nil || report.SchemaVersion != 1 || !report.Source.IP.IsValid() || len(report.Devices) == 0 || report.UpdatedAt.IsZero() || report.ExpiresAt.IsZero() {
		return nil, errors.New("hub returned an invalid network report; check the hub CLI and agent versions")
	}
	if report.Source.IP.String() != cfg.OverlayIP {
		return nil, fmt.Errorf("network source differs from the saved hub; run deepai-connect setup --hub %s", cfg.Hub)
	}
	return &report, nil
}

func displayNetworkName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, name)
}

func printNetwork(out io.Writer, r *hostnet.NetworkReport, cfg *Config) {
	via := "local agent"
	if cfg != nil {
		via = cfg.Hub + " via SSH"
	}
	fmt.Fprintf(out, "Measured from: %s (%s; %s)\n", displayNetworkName(r.Source.Name), r.Source.IP, via)
	fmt.Fprintf(out, "Snapshot updated: %s; expires: %s\n", r.UpdatedAt.Format(time.RFC3339), r.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(out, "Configured ranges: mesh %s | pods %s | services %s\n\n", r.MeshCIDR, r.PodCIDR, r.ServiceCIDR)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DEVICE\tMESH IP\tPATH FOUND\tTUNNEL RTT\tRESULT")
	now, cached := time.Now(), false
	for _, d := range r.Devices {
		path, rtt, result := d.Path, "—", d.TunnelResult
		if d.RTTMs != nil {
			rtt = fmt.Sprintf("%.1f ms", *d.RTTMs)
		}
		if d.Source {
			path, rtt, result = "—", "—", "source"
		} else if d.Cached {
			cached = true
			path += networkSampleAge(d.PathAt, now)
			result += networkSampleAge(d.TunnelAt, now)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", displayNetworkName(d.Name), d.IP, path, rtt, result)
	}
	_ = w.Flush()
	if cached {
		fmt.Fprintln(out, "\nAged rows reuse recent measurements, up to 30s old.")
	}
	if r.Error != "" {
		fmt.Fprintf(out, "\nNote: %s\n", r.Error)
	}
	if !r.Complete {
		fmt.Fprintln(out, "Partial report: some measurements were not completed.")
	}
	fmt.Fprintln(out, "\nPath and RTT are separate samples. A tunnel reply does not test applications.")
}

func networkSampleAge(at *time.Time, now time.Time) string {
	if at == nil {
		return " (cached)"
	}
	age := max(time.Duration(0), now.Sub(*at)).Truncate(time.Second)
	return fmt.Sprintf(" (%s ago)", age)
}

func networkWarnings(ctx context.Context, cfg Config, out io.Writer) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := remoteNetwork(ctx, cfg)
	if err != nil {
		fmt.Fprintf(out, "WARN network: %v\n", err)
		return
	}
	replies, peers, cached := 0, 0, 0
	for _, d := range r.Devices {
		if !d.Source {
			peers++
			if d.TunnelResult == "reply" {
				replies++
			}
			if d.Cached {
				cached++
			}
		}
	}
	fmt.Fprintf(out, "Network: %d/%d peers replied from %s", replies, peers, displayNetworkName(r.Source.Name))
	if cached > 0 {
		fmt.Fprintf(out, " (cached measurements: %d)", cached)
	}
	fmt.Fprintln(out)
	if !r.Complete || r.Error != "" || replies != peers {
		fmt.Fprintln(out, "WARN network: missing measurements or replies; run deepai-connect network")
	}
}
