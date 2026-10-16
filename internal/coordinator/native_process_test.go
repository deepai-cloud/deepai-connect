//go:build integration || vpsintegration

package coordinator

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

const nativeChildMode = "DEEPAI_NATIVE_TEST_CHILD"

// Upstream port-mapping goroutines can outlive tsnet.Close. Keep their global
// environment knobs immutable for the entire child process, including cleanup.
// Reusing this test binary preserves race instrumentation when built with -race.
func runNativeTestProcess(t *testing.T, mode string, timeout time.Duration, environment ...string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name, _, _ := strings.Cut(t.Name(), "/")
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+regexp.QuoteMeta(name)+"$", "-test.timeout="+timeout.String(), "-test.v")
	cmd.Env = append(os.Environ(), nativeChildMode+"="+mode, "TS_DISABLE_LOGTAIL=true", "TS_DISABLE_PORTMAPPER=true")
	cmd.Env = append(cmd.Env, environment...)
	// Forward progress immediately: the external test holds a live session at
	// a file barrier while another process performs reverse probes and faults.
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("native %s process: %v", mode, err)
	}
}
