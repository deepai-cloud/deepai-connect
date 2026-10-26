package unified

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

const hostHelp = `Usage: deepai-connect host start|stop|status [--dir PATH] [--json]
       deepai-connect host startup enable|disable|status [--dir PATH] [--json]

Manage an existing Linux installation (root and systemd required).
Start restores the mesh and waits for readiness before starting Kubernetes.
Stop stops Kubernetes control services before the mesh. K3s retains container
processes: this is not a workload drain or a guarantee that all compute stopped.
Use VM stop for a complete VM shutdown; plan workload availability first.

Startup controls machine-boot enablement, not login startup. Changing it never
starts or stops services now. Start/stop do not change the boot preference.
Identity, enrollment, cluster data and unrelated host rules are retained.
Setup/join is separate; incomplete installations must use resume first.
Status reports services and desired/observed startup state, not cluster health.
Diagnose readiness with inspect, doctor and the two units' journalctl logs.
`

const hostStopNote = "Stopping host services preserves K3s container processes; workloads are not drained and may keep running without mesh connectivity."

type hostServiceState struct {
	Unit   string `json:"unit"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
	Boot   string `json:"boot"`
}

type hostFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type hostReport struct {
	SchemaVersion int                `json:"schemaVersion"`
	Action        string             `json:"action"`
	Platform      string             `json:"platform"`
	Scope         string             `json:"scope"`
	Name          string             `json:"name,omitempty"`
	Role          string             `json:"role,omitempty"`
	Phase         string             `json:"phase,omitempty"`
	Startup       *bool              `json:"startupEnabled,omitempty"`
	Services      []hostServiceState `json:"services"`
	Warnings      []string           `json:"warnings,omitempty"`
	Error         *hostFailure       `json:"error,omitempty"`
}

func runHost(ctx context.Context, args []string) error {
	return runHostTo(ctx, args, os.Stdout)
}

func runHostTo(ctx context.Context, args []string, out io.Writer) error {
	help := len(args) == 0
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			help = true
		}
	}
	if help {
		_, err := fmt.Fprint(out, hostHelp)
		return err
	}
	report := hostReport{SchemaVersion: 1, Action: args[0], Platform: runtime.GOOS, Scope: "machine-boot", Services: []hostServiceState{}}
	asJSON := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		switch arg {
		case "--json", "--json=true":
			asJSON = true
		case "--json=false":
			asJSON = false
		}
	}
	finish := func(code string, err error) error {
		if err != nil {
			report.Error = &hostFailure{code, err.Error()}
		}
		if asJSON {
			if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil && err == nil {
				return encodeErr
			}
		} else if err == nil {
			fmt.Fprintf(out, "%s %s: phase=%s; automatic machine-boot startup=%t\n", report.Role, report.Name, report.Phase, *report.Startup)
			for _, service := range report.Services {
				fmt.Fprintf(out, "%s: %s/%s; boot=%s\n", service.Unit, service.Active, service.Sub, service.Boot)
			}
			for _, warning := range report.Warnings {
				fmt.Fprintln(out, "Note:", warning)
			}
		}
		return err
	}
	action, flags := args[0], args[1:]
	if action == "startup" {
		if len(flags) == 0 {
			return finish("invalid_arguments", errors.New("host startup requires enable, disable or status"))
		}
		action, flags = "startup-"+flags[0], flags[1:]
		report.Action = action
	}
	fs := flag.NewFlagSet("host "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	dir := fs.String("dir", defaultDir, "private installation directory")
	fs.BoolVar(&asJSON, "json", asJSON, "structured state and errors")
	if err := parse(fs, flags); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return finish("invalid_arguments", err)
	}
	switch action {
	case "start", "stop", "status", "startup-enable", "startup-disable", "startup-status":
	default:
		return finish("invalid_arguments", fmt.Errorf("unknown host action %q", action))
	}
	if err := hostRequired(); err != nil {
		return finish("host_required", err)
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return finish("invalid_arguments", err)
	}
	// Refuse absent state before acquiring a lock, which creates private storage.
	i, err := loadInstallation(absolute)
	if err != nil {
		return finish("installation_unavailable", err)
	}
	mutation := action != "status" && action != "startup-status"
	if mutation {
		unlock, err := platform.Lock(absolute)
		if err != nil {
			return finish("installation_locked", err)
		}
		defer unlock()
		runtimeUnlock, err := platform.Lock(filepath.Join(defaultDir, "runtime-lock"))
		if err != nil {
			return finish("installation_locked", err)
		}
		defer runtimeUnlock()
		i, err = loadInstallation(absolute)
		if err != nil {
			return finish("installation_unavailable", err)
		}
	}
	report.Name, report.Role, report.Phase = i.Config.Name, i.Config.Role, i.Phase
	code, err := operateHost(ctx, absolute, i, action, cluster.ExecRunner{}, hostnet.WaitReady, nil, &report)
	return finish(code, err)
}

// Bound systemd/D-Bus calls independently of readiness loops so an unavailable
// manager still yields a structured failure. Stop allows systemd's usual 90s
// service timeout; read-only probes must return much sooner.
type hostCommandRunner struct{ cluster.Runner }

func (r hostCommandRunner) Run(ctx context.Context, input []byte, command string, args ...string) ([]byte, error) {
	if command == "systemctl" {
		timeout := 2 * time.Minute
		if len(args) > 0 && (args[0] == "show" || args[0] == "is-active") {
			timeout = 15 * time.Second
		}
		bounded, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ctx = bounded
	}
	return r.Runner.Run(ctx, input, command, args...)
}

// operateHost never installs or enrolls. Narrow injected readiness functions let
// tests exercise service ordering without a live mesh or systemd manager.
func operateHost(ctx context.Context, dir string, i *installation, action string, runner cluster.Runner, waitNetwork func(context.Context, string) error, waitCluster func(context.Context, *cluster.Manager) error, report *hostReport) (string, error) {
	runner = hostCommandRunner{runner}
	automatic, err := cluster.StartupEnabled(dir)
	if err != nil {
		return "invalid_startup_preference", err
	}
	report.Startup = &automatic
	m, err := cluster.Load(i.Config.DataDir, runner)
	if err != nil {
		return "installation_unavailable", fmt.Errorf("load installed cluster; resume incomplete installation first: %w", err)
	}
	expected, err := cluster.New(i.Config, runner)
	if err != nil {
		return "installation_unavailable", err
	}
	if !reflect.DeepEqual(m.Config, expected.Config) {
		return "installation_mismatch", errors.New("unified and cluster service configuration differ; explicit recovery required")
	}
	agent, err := agentUnit(i.Config)
	if err != nil {
		return "installation_mismatch", err
	}
	units := []struct{ name, content string }{{cluster.AgentUnitName, agent}, {cluster.UnitName, m.Unit()}}
	for _, unit := range units {
		content, err := platform.ReadFile(filepath.Join(i.Config.SystemdDir, unit.name))
		if err != nil || string(content) != unit.content {
			return "unit_ownership_conflict", fmt.Errorf("%s is missing, unsafe or differs from this installation; restore the owned unit before changing lifecycle", unit.name)
		}
	}
	readStates := func() error {
		report.Services = []hostServiceState{}
		for _, unit := range units {
			state, err := readHostUnit(ctx, runner, i.Config.SystemdDir, unit.name)
			if err != nil {
				return err
			}
			report.Services = append(report.Services, state)
		}
		return nil
	}
	if err := readStates(); err != nil {
		return "systemd_state_unavailable", err
	}
	if action != "status" && action != "startup-status" && i.Phase != "ready" {
		return "installation_incomplete", errors.New("installation is incomplete; run resume before changing host lifecycle")
	}
	var operationErr error
	switch action {
	case "start":
		if _, operationErr = runner.Run(ctx, nil, "systemctl", "start", cluster.AgentUnitName); operationErr == nil {
			wait, cancel := context.WithTimeout(ctx, 90*time.Second)
			operationErr = waitNetwork(wait, i.Config.AgentStateDir)
			cancel()
		}
		if operationErr == nil {
			_, operationErr = runner.Run(ctx, nil, "systemctl", "start", "--no-block", cluster.UnitName)
		}
		if operationErr == nil {
			if waitCluster != nil {
				operationErr = waitCluster(ctx, m)
			} else {
				operationErr = m.WaitReady(ctx)
			}
		}
	case "stop":
		report.Warnings = append(report.Warnings, hostStopNote)
		if _, operationErr = runner.Run(ctx, nil, "systemctl", "stop", cluster.UnitName); operationErr == nil {
			var stopped hostServiceState
			stopped, operationErr = readHostUnit(ctx, runner, i.Config.SystemdDir, cluster.UnitName)
			if operationErr == nil && stopped.Active != "inactive" {
				operationErr = errors.New("Kubernetes service did not stop; mesh retained")
			}
			if operationErr == nil {
				_, operationErr = runner.Run(ctx, nil, "systemctl", "stop", cluster.AgentUnitName)
			}
		}
	case "startup-enable", "startup-disable":
		requested := action == "startup-enable"
		// Persist first so a partial systemctl failure cannot turn a requested
		// manual installation back into automatic boot during resume.
		if operationErr = cluster.SetStartupEnabled(dir, requested); operationErr == nil {
			automatic = requested
			boot := "enable"
			if !automatic {
				boot = "disable"
			}
			_, operationErr = runner.Run(ctx, nil, "systemctl", boot, cluster.AgentUnitName, cluster.UnitName)
		}
	case "status", "startup-status":
	}
	if action != "status" && action != "startup-status" {
		if err := readStates(); err != nil {
			if operationErr == nil {
				return "systemd_state_unavailable", err
			}
			report.Warnings = append(report.Warnings, "Could not read complete service state after the failed operation.")
		}
	}
	for _, service := range report.Services {
		if operationErr == nil && (action == "start" && service.Active != "active" || action == "stop" && service.Active != "inactive") {
			operationErr = fmt.Errorf("%s did not reach the requested service state", service.Unit)
		}
		matches := automatic && service.Boot == "enabled" || !automatic && service.Boot == "disabled"
		if !matches {
			if operationErr == nil && (action == "startup-enable" || action == "startup-disable") {
				operationErr = errors.New("systemd boot enablement did not reach the saved preference; repeat the startup command")
			}
			report.Warnings = append(report.Warnings, service.Unit+" boot state differs from the saved preference; repeat host startup enable/disable to reconcile.")
		}
	}
	if operationErr != nil {
		return "operation_failed", fmt.Errorf("host %s failed; saved identity and data retained: %w", action, operationErr)
	}
	return "", nil
}

func readHostUnit(ctx context.Context, runner cluster.Runner, unitDir, name string) (hostServiceState, error) {
	state := hostServiceState{Unit: name}
	data, err := runner.Run(ctx, nil, "systemctl", "show", "--all", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload", name)
	if err != nil {
		return state, fmt.Errorf("read %s through systemd: %w", name, err)
	}
	properties := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return state, errors.New("invalid systemd property output")
		}
		if _, duplicate := properties[key]; duplicate {
			return state, errors.New("duplicate systemd property")
		}
		properties[key] = value
	}
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"} {
		if _, exists := properties[key]; !exists {
			return state, fmt.Errorf("systemd omitted %s for %s", key, name)
		}
	}
	if properties["LoadState"] != "loaded" || properties["FragmentPath"] != filepath.Join(unitDir, name) || properties["DropInPaths"] != "" || properties["NeedDaemonReload"] != "no" {
		return state, fmt.Errorf("%s has a foreign, overridden, stale or unloaded systemd definition; inspect it before retrying", name)
	}
	state.Active, state.Sub, state.Boot = properties["ActiveState"], properties["SubState"], properties["UnitFileState"]
	if state.Active == "" || state.Sub == "" || state.Boot == "" {
		return state, fmt.Errorf("systemd returned incomplete state for %s", name)
	}
	return state, nil
}
