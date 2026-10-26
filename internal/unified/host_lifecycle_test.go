package unified

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

type hostTestRunner struct {
	unitDir       string
	calls         []string
	active, boot  map[string]string
	fail          string
	properties    map[string]string
	ignoreActions bool
}

func (r *hostTestRunner) Run(_ context.Context, _ []byte, command string, args ...string) ([]byte, error) {
	call := command + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if r.fail != "" && strings.Contains(call, r.fail) {
		return nil, errors.New("simulated command failure")
	}
	if command != "systemctl" {
		return nil, errors.New("unexpected command")
	}
	if args[0] == "show" {
		name := args[len(args)-1]
		properties := map[string]string{"LoadState": "loaded", "ActiveState": r.active[name], "SubState": "running", "UnitFileState": r.boot[name], "FragmentPath": filepath.Join(r.unitDir, name), "DropInPaths": "", "NeedDaemonReload": "no"}
		for k, v := range r.properties {
			properties[k] = v
		}
		var b strings.Builder
		for _, k := range []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"} {
			if properties[k] != "omit" {
				b.WriteString(k + "=" + properties[k] + "\n")
			}
		}
		return []byte(b.String()), nil
	}
	if r.ignoreActions {
		return nil, nil
	}
	for _, name := range args[1:] {
		if strings.HasPrefix(name, "--") {
			continue
		}
		switch args[0] {
		case "start":
			r.active[name] = "active"
		case "stop":
			r.active[name] = "inactive"
		case "enable":
			r.boot[name] = "enabled"
		case "disable":
			r.boot[name] = "disabled"
		default:
			return nil, errors.New("unexpected action")
		}
	}
	return nil, nil
}

func hostFixture(t *testing.T) (string, *installation, *hostTestRunner) {
	t.Helper()
	dir := t.TempDir()
	i := testInstallation(dir)
	i.Phase = "ready"
	i.Config.SystemdDir = filepath.Join(dir, "units")
	m, err := cluster.New(i.Config, nil)
	if err != nil {
		t.Fatal(err)
	}
	i.Config = m.Config
	if err = m.Save(); err != nil {
		t.Fatal(err)
	}
	if err = saveInstallation(dir, i); err != nil {
		t.Fatal(err)
	}
	agent, err := agentUnit(i.Config)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{cluster.AgentUnitName: agent, cluster.UnitName: m.Unit()} {
		if err = platform.WriteFile(filepath.Join(i.Config.SystemdDir, name), []byte(data), false); err != nil {
			t.Fatal(err)
		}
	}
	if err = platform.WriteFile(filepath.Join(dir, "network", "identity-preservation-fixture"), []byte("private-identity-fixture"), false); err != nil {
		t.Fatal(err)
	}
	return dir, i, &hostTestRunner{unitDir: i.Config.SystemdDir, active: map[string]string{cluster.AgentUnitName: "inactive", cluster.UnitName: "inactive"}, boot: map[string]string{cluster.AgentUnitName: "enabled", cluster.UnitName: "enabled"}}
}

func hostActions(r *hostTestRunner) []string {
	var actions []string
	for _, call := range r.calls {
		if !strings.Contains(call, "systemctl show ") {
			actions = append(actions, call)
		}
	}
	return actions
}

func TestHostStartOrdersMeshAndReadinessBeforeCompute(t *testing.T) {
	dir, i, r := hostFixture(t)
	before, err := os.ReadFile(filepath.Join(dir, "unified.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report hostReport
	waitNetwork := func(_ context.Context, path string) error {
		r.calls = append(r.calls, "mesh-ready")
		if path != i.Config.AgentStateDir {
			t.Fatal(path)
		}
		return nil
	}
	waitCluster := func(_ context.Context, m *cluster.Manager) error {
		r.calls = append(r.calls, "cluster-ready")
		if m.Config.Name != i.Config.Name {
			t.Fatal(m.Config.Name)
		}
		return nil
	}
	code, err := operateHost(context.Background(), dir, i, "start", r, waitNetwork, waitCluster, &report)
	want := []string{"systemctl start " + cluster.AgentUnitName, "mesh-ready", "systemctl start --no-block " + cluster.UnitName, "cluster-ready"}
	if err != nil || code != "" || !reflect.DeepEqual(hostActions(r), want) {
		t.Fatalf("%s %v actions=%v", code, err, hostActions(r))
	}
	after, _ := os.ReadFile(filepath.Join(dir, "unified.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("installation rewritten")
	}
	identity, _ := os.ReadFile(filepath.Join(dir, "network", "identity-preservation-fixture"))
	if string(identity) != "private-identity-fixture" {
		t.Fatal("identity changed")
	}
	if _, err = os.Stat(filepath.Join(dir, "host-startup.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("start changed boot preference")
	}
	if len(report.Services) != 2 || report.Services[0].Active != "active" || report.Services[1].Active != "active" {
		t.Fatal(report)
	}
}

func TestHostReadinessFailureLeavesMeshAndNeverStartsCompute(t *testing.T) {
	dir, i, r := hostFixture(t)
	var report hostReport
	code, err := operateHost(context.Background(), dir, i, "start", r, func(context.Context, string) error { return errors.New("network not ready") }, nil, &report)
	if err == nil || code != "operation_failed" || !reflect.DeepEqual(hostActions(r), []string{"systemctl start " + cluster.AgentUnitName}) {
		t.Fatalf("%s %v %v", code, err, hostActions(r))
	}
	if report.Services[0].Active != "active" || report.Services[1].Active != "inactive" {
		t.Fatal(report)
	}
}

func TestHostStopOrderAndFailurePreserveMesh(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "compute-failure"}[fail], func(t *testing.T) {
			dir, i, r := hostFixture(t)
			r.active[cluster.AgentUnitName], r.active[cluster.UnitName] = "active", "active"
			if fail {
				r.fail = "stop " + cluster.UnitName
			}
			var report hostReport
			_, err := operateHost(context.Background(), dir, i, "stop", r, nil, nil, &report)
			want := []string{"systemctl stop " + cluster.UnitName}
			if !fail {
				want = append(want, "systemctl stop "+cluster.AgentUnitName)
			}
			if (err != nil) != fail || !reflect.DeepEqual(hostActions(r), want) {
				t.Fatalf("%v %v", err, hostActions(r))
			}
			if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0], "container processes") {
				t.Fatal("omitted workload stop limit")
			}
		})
	}
}

func TestHostStartupChangesOnlyEnablementAndPersistsPartialFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			dir, i, r := hostFixture(t)
			r.active[cluster.AgentUnitName], r.active[cluster.UnitName] = "active", "active"
			if fail {
				r.fail = "disable "
			}
			var report hostReport
			_, err := operateHost(context.Background(), dir, i, "startup-disable", r, nil, nil, &report)
			if (err != nil) != fail {
				t.Fatal(err)
			}
			enabled, err := cluster.StartupEnabled(dir)
			if err != nil || enabled {
				t.Fatalf("preference=%t %v", enabled, err)
			}
			want := []string{"systemctl disable " + cluster.AgentUnitName + " " + cluster.UnitName}
			if !reflect.DeepEqual(hostActions(r), want) {
				t.Fatal(hostActions(r))
			}
			if report.Services[0].Active != "active" || report.Services[1].Active != "active" || *report.Startup {
				t.Fatal(report)
			}
			if fail && len(report.Warnings) != 2 {
				t.Fatal("partial failure drift not reported", report)
			}
		})
	}
}

func TestHostStatusReadOnlyAndUnknownIsNotStopped(t *testing.T) {
	dir, i, r := hostFixture(t)
	r.active[cluster.AgentUnitName] = "activating"
	var report hostReport
	_, err := operateHost(context.Background(), dir, i, "status", r, nil, nil, &report)
	if err != nil || len(hostActions(r)) != 0 || report.Services[0].Active != "activating" {
		t.Fatalf("%v %#v", err, report)
	}
	if _, err = os.Stat(filepath.Join(dir, "host-startup.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("status saved preference")
	}
}

func TestHostRefusesForeignOrUncertainUnitsBeforeAnyMutation(t *testing.T) {
	for _, fixture := range []string{"content", "symlink", "dropin", "fragment", "stale", "unloaded", "missing-property", "incomplete"} {
		t.Run(fixture, func(t *testing.T) {
			dir, i, r := hostFixture(t)
			r.properties = map[string]string{}
			switch fixture {
			case "content":
				if err := os.WriteFile(filepath.Join(i.Config.SystemdDir, cluster.UnitName), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if runtime.GOOS == "windows" {
					t.Skip("symlink privileges vary")
				}
				path := filepath.Join(i.Config.SystemdDir, cluster.UnitName)
				if err := os.Rename(path, path+"-target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-target", path); err != nil {
					t.Fatal(err)
				}
			case "dropin":
				r.properties["DropInPaths"] = "/etc/systemd/system/foreign.conf"
			case "fragment":
				r.properties["FragmentPath"] = "/etc/systemd/system/foreign.service"
			case "stale":
				r.properties["NeedDaemonReload"] = "yes"
			case "unloaded":
				r.properties["LoadState"] = "not-found"
			case "missing-property":
				r.properties["ActiveState"] = "omit"
			case "incomplete":
				i.Phase = "network"
			}
			var report hostReport
			_, err := operateHost(context.Background(), dir, i, "startup-disable", r, nil, nil, &report)
			if err == nil || len(hostActions(r)) != 0 {
				t.Fatalf("%v %v", err, hostActions(r))
			}
			if _, err = os.Stat(filepath.Join(dir, "host-startup.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal changed preference")
			}
		})
	}
}

func TestAgentResumeRespectsManualStartup(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		dir, i, r := hostFixture(t)
		if err := cluster.SetStartupEnabled(dir, enabled); err != nil {
			t.Fatal(err)
		}
		ready := false
		err := startAgentWith(context.Background(), i, r, func(context.Context, string) error { ready = true; return nil })
		if err != nil || !ready {
			t.Fatalf("%v ready=%t", err, ready)
		}
		expected := "disabled"
		if enabled {
			expected = "enabled"
		}
		if r.boot[cluster.AgentUnitName] != expected || r.active[cluster.AgentUnitName] != "active" {
			t.Fatal(r.boot, r.active)
		}
		// A second resume remains idempotent and cannot change the preference.
		if err := startAgentWith(context.Background(), i, r, func(context.Context, string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if actual, err := cluster.StartupEnabled(dir); err != nil || actual != enabled {
			t.Fatal(actual, err)
		}
	}
}

func TestHostStructuredErrorsAndHelp(t *testing.T) {
	for _, args := range [][]string{{"bogus", "--json"}, {"startup", "--json"}, {"status", "--bad", "--json"}} {
		var out bytes.Buffer
		if err := runHostTo(context.Background(), args, &out); err == nil {
			t.Fatal("invalid args accepted")
		}
		var report hostReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Error == nil || report.Error.Code != "invalid_arguments" {
			t.Fatalf("%v %s", err, out.String())
		}
	}
	if runtime.GOOS != "linux" {
		var out bytes.Buffer
		if err := runHostTo(context.Background(), []string{"status", "--json"}, &out); err == nil {
			t.Fatal("unsupported host accepted")
		}
		var report hostReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Error == nil || report.Error.Code != "host_required" {
			t.Fatalf("%v %s", err, out.String())
		}
	}
	var out bytes.Buffer
	if err := runHostTo(context.Background(), []string{"startup", "--help"}, &out); err != nil || !strings.Contains(out.String(), "machine-boot") {
		t.Fatalf("%v %s", err, out.String())
	}
}

func TestHostRequiresObservedPostcondition(t *testing.T) {
	for _, action := range []string{"stop", "startup-disable", "start"} {
		t.Run(action, func(t *testing.T) {
			dir, i, r := hostFixture(t)
			r.ignoreActions = true
			if action == "stop" {
				r.active[cluster.AgentUnitName], r.active[cluster.UnitName] = "active", "active"
			}
			var report hostReport
			ready := func(context.Context, string) error { return nil }
			clusterReady := func(context.Context, *cluster.Manager) error { return nil }
			code, err := operateHost(context.Background(), dir, i, action, r, ready, clusterReady, &report)
			if err == nil || code != "operation_failed" {
				t.Fatalf("%s %v", code, err)
			}
			if action == "stop" && len(hostActions(r)) != 1 {
				t.Fatal("stopped mesh without confirmed compute stop", hostActions(r))
			}
		})
	}
}

func TestHostRefusesMismatchedInstallationConfig(t *testing.T) {
	dir, i, r := hostFixture(t)
	i.Config.OverlayIP = "100.64.0.99"
	var report hostReport
	code, err := operateHost(context.Background(), dir, i, "start", r, nil, nil, &report)
	if err == nil || code != "installation_mismatch" || len(hostActions(r)) != 0 {
		t.Fatalf("%s %v %v", code, err, hostActions(r))
	}
}

func TestHostSystemdCallsHaveBoundedDeadlines(t *testing.T) {
	for _, action := range []string{"show", "is-active", "start", "stop", "enable", "disable"} {
		t.Run(action, func(t *testing.T) {
			r := hostCommandRunner{workerRunner(func(ctx context.Context, _ []byte, command string, args ...string) ([]byte, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("systemd call has no deadline")
				}
				limit := 2 * time.Minute
				if action == "show" || action == "is-active" {
					limit = 15 * time.Second
				}
				if remaining := time.Until(deadline); remaining <= 0 || remaining > limit {
					t.Fatal("invalid deadline", remaining)
				}
				return nil, nil
			})}
			if _, err := r.Run(context.Background(), nil, "systemctl", action, cluster.UnitName); err != nil {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := hostCommandRunner{workerRunner(func(ctx context.Context, _ []byte, _ string, _ ...string) ([]byte, error) { return nil, ctx.Err() })}
	if _, err := r.Run(ctx, nil, "systemctl", "show", cluster.UnitName); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation was lost", err)
	}
}

func TestHostStartupEnableIsIdempotentAndDoesNotStartServices(t *testing.T) {
	dir, i, r := hostFixture(t)
	if err := cluster.SetStartupEnabled(dir, false); err != nil {
		t.Fatal(err)
	}
	r.boot[cluster.AgentUnitName], r.boot[cluster.UnitName] = "disabled", "disabled"
	for range 2 {
		var report hostReport
		if code, err := operateHost(context.Background(), dir, i, "startup-enable", r, nil, nil, &report); err != nil {
			t.Fatal(code, err)
		}
		if !*report.Startup || len(report.Warnings) != 0 {
			t.Fatal(report)
		}
		if r.active[cluster.AgentUnitName] != "inactive" || r.active[cluster.UnitName] != "inactive" {
			t.Fatal("startup enable started services")
		}
	}
	for _, call := range hostActions(r) {
		if call != "systemctl enable "+cluster.AgentUnitName+" "+cluster.UnitName {
			t.Fatal(call)
		}
	}
}
