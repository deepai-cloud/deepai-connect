package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
)

func testNetworkReport() *hostnet.NetworkReport {
	now := time.Now().UTC()
	rtt := 80.0
	return &hostnet.NetworkReport{
		SchemaVersion: 1, Source: hostnet.NetworkSource{Name: "hub", IP: netip.MustParseAddr("100.96.0.1")},
		UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Complete: true,
		MeshCIDR: netip.MustParsePrefix("100.96.0.0/16"), PodCIDR: netip.MustParsePrefix("10.42.0.0/16"), ServiceCIDR: netip.MustParsePrefix("10.43.0.0/16"),
		Devices: []hostnet.NetworkDevice{
			{Name: "hub", IP: netip.MustParseAddr("100.96.0.1"), Source: true, Path: "unknown", PathResult: "not tested", TunnelResult: "not tested"},
			{Name: "worker", IP: netip.MustParseAddr("100.96.0.4"), Path: "relay", Relay: "derp", PathResult: "reply", RTTMs: &rtt, TunnelResult: "reply"},
		},
	}
}

func TestNetworkTargetDoesNotFallBackFromSavedHub(t *testing.T) {
	cfg := desktopTestConfig(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		_, err := networkTarget(goos, false, false)
		if (err != nil) != (goos != "linux") {
			t.Fatalf("absent config on %s: %v", goos, err)
		}
	}
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		got, err := networkTarget(goos, false, false)
		if err != nil || got == nil || *got != cfg {
			t.Fatalf("saved hub on %s: %+v %v", goos, got, err)
		}
		if _, err = networkTarget(goos, false, true); err == nil {
			t.Fatal("remote mode accepted local directory override")
		}
	}
	if got, err := networkTarget("linux", true, true); got != nil || err != nil {
		t.Fatalf("explicit local: %+v %v", got, err)
	}
	for _, goos := range []string{"darwin", "windows"} {
		if _, err := networkTarget(goos, true, false); err == nil {
			t.Fatalf("allowed local agent on %s", goos)
		}
	}
	p, _ := configPath()
	if err := os.WriteFile(p, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := networkTarget("linux", false, false); err == nil {
		t.Fatal("malformed config fell back to local")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p+".missing", p); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := networkTarget("linux", false, false); err == nil {
		t.Fatal("dangling config symlink fell back to local")
	}
}

func TestNetworkRemoteScopeAndJSON(t *testing.T) {
	cfg := desktopTestConfig(t)
	cfg.StateDir = "/srv/owner's connect"
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	want := testNetworkReport()
	want.Complete, want.Error = false, "network check already running"
	desktopMockRunner(t, func(ctx context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
		command := args[len(args)-1]
		if !strings.Contains(command, "'network' '--local' '--dir' '/srv/owner'\"'\"'s connect' '--json'") {
			t.Fatalf("remote source or directory lost: %s", command)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("SSH has no overall waiting limit")
		}
		return json.NewEncoder(out).Encode(want)
	})
	var out bytes.Buffer
	if err := networkCommand(context.Background(), []string{"--json"}, "darwin", &out); err != nil {
		t.Fatal(err)
	}
	var got hostnet.NetworkReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.Complete || got.Error != want.Error || got.Devices[0].RTTMs != nil || *got.Devices[1].RTTMs != 80 {
		t.Fatalf("partial JSON changed or polluted: %s; %v", out.String(), err)
	}
	out.Reset()
	printNetwork(&out, want, &cfg)
	if text := out.String(); !strings.Contains(text, "Measured from: hub") || !strings.Contains(text, "via SSH") || !strings.Contains(text, "80.0 ms") || !strings.Contains(text, "Partial report") {
		t.Fatalf("misleading human output: %s", text)
	}
}

func TestNetworkJSONArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{"--json", "--bogus"}, {"--bogus", "--json"}, {"--json", "unexpected"}, {"--json", "--dir"}} {
		var out bytes.Buffer
		err := networkCommand(context.Background(), args, "darwin", &out)
		if err == nil || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"error"`) {
			t.Fatalf("%v: missing JSON error: %s (%v)", args, out.String(), err)
		}
	}
}

func TestNetworkNamesCannotInjectTerminalLinesOrEscapes(t *testing.T) {
	r := testNetworkReport()
	r.Source.Name = "hub\nspoofed\tcolumn\x1b[31m"
	r.Devices[1].Name = "worker\r\nFAKE ROW\x1b]0;title\a"
	var out bytes.Buffer
	printNetwork(&out, r, nil)
	if text := out.String(); strings.ContainsAny(text, "\x1b\r\a") || strings.Contains(text, "\nspoofed") || strings.Contains(text, "\nFAKE ROW") {
		t.Fatalf("hostname changed terminal structure: %q", text)
	}
}

func TestNetworkCachedMeasurementsShowSeparateAges(t *testing.T) {
	for _, reply := range []bool{true, false} {
		r := testNetworkReport()
		pathAt, tunnelAt := time.Now().Add(-8*time.Second), time.Now().Add(-4*time.Second)
		d := &r.Devices[1]
		d.Cached, d.PathAt, d.TunnelAt = true, &pathAt, &tunnelAt
		if !reply {
			d.TunnelResult, d.RTTMs = "no reply", nil
		}
		var out bytes.Buffer
		printNetwork(&out, r, nil)
		text := out.String()
		if !regexp.MustCompile(`relay \([89]s ago\)`).MatchString(text) || !regexp.MustCompile(d.TunnelResult+` \([45]s ago\)`).MatchString(text) || !strings.Contains(text, "reuse recent measurements, up to 30s old") {
			t.Fatalf("cached path and tunnel samples lost their ages: %s", text)
		}
		if strings.Contains(text, "80.0 ms") != reply {
			t.Fatalf("cached reply or failed measurement changed: %s", text)
		}
		d.Cached = false
		out.Reset()
		printNetwork(&out, r, nil)
		if text = out.String(); strings.Contains(text, "ago)") || strings.Contains(text, "reuse recent measurements") {
			t.Fatalf("fresh measurements were labeled cached: %s", text)
		}
	}
}

func TestNetworkDoctorLabelsCachedMeasurements(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cached bool
		reply  bool
	}{
		{"fresh reply", false, true},
		{"cached reply", true, true},
		{"cached failure", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := desktopTestConfig(t)
			r := testNetworkReport()
			r.Devices[1].Cached = tc.cached
			if !tc.reply {
				r.Devices[1].TunnelResult, r.Devices[1].RTTMs = "no reply", nil
			}
			desktopMockRunner(t, func(_ context.Context, _ string, _ []string, _ io.Reader, out, _ io.Writer) error {
				return json.NewEncoder(out).Encode(r)
			})
			var out bytes.Buffer
			networkWarnings(context.Background(), cfg, &out)
			text := out.String()
			if strings.Contains(text, "cached measurements: 1") != tc.cached || strings.Contains(text, "WARN network") == tc.reply {
				t.Fatalf("doctor hid cached observations or changed failure reporting: %s", text)
			}
		})
	}
}

func TestNetworkFailureKindsAndJSONEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name, stdout, stderr string
		processErr           error
		upgrade              bool
	}{
		{"old CLI", "", `deepai-connect: unknown command "network"; run deepai-connect --help`, errors.New("exit 1"), true},
		{"SSH", "", "Permission denied", errors.New("exit 255"), false},
		{"missing socket", `{"schemaVersion":1,"error":"local host agent unavailable: no such file"}`, "", errors.New("exit 1"), false},
		{"invalid JSON", "not JSON", "", nil, false},
		{"empty report", `{"schemaVersion":1}`, "", nil, false},
		{"trailing JSON", `{"schemaVersion":1} {}`, "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := desktopTestConfig(t)
			if err := saveConfig(cfg); err != nil {
				t.Fatal(err)
			}
			desktopMockRunner(t, func(_ context.Context, _ string, _ []string, _ io.Reader, out, stderr io.Writer) error {
				io.WriteString(out, tc.stdout)
				io.WriteString(stderr, tc.stderr)
				return tc.processErr
			})
			var out bytes.Buffer
			err := networkCommand(context.Background(), []string{"--json"}, "darwin", &out)
			if err == nil || strings.Contains(err.Error(), "upgrade") != tc.upgrade {
				t.Fatalf("wrong failure classification: %v", err)
			}
			var envelope struct {
				SchemaVersion int
				Error         string
			}
			if json.Unmarshal(out.Bytes(), &envelope) != nil || envelope.SchemaVersion != 1 || envelope.Error == "" {
				t.Fatalf("failure is not a JSON envelope: %s", out.String())
			}
		})
	}
}
