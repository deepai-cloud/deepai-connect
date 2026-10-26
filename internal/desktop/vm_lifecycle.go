package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

const vmLifecycleNotes = "VM state is not Kubernetes readiness. Stopping the VM interrupts its workloads. Connect never deletes or re-enrolls it; use doctor after starting."
const vmStartupNotes = "This controls only Connect's next-login trigger, not machine-boot startup or the current VM. Multipass may independently restore previously running VMs when its daemon starts. macOS Login Items permission can also block execution. Gateway Node/Ollama and native mesh startup are separate."

var vmLifecycleName = regexp.MustCompile(`^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)

type vmLifecycleReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	Name          string `json:"name"`
	Action        string `json:"action"`
	State         string `json:"state"`
	Changed       bool   `json:"changed"`
	Notes         string `json:"notes"`
}

type vmStartupReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	Name          string `json:"name"`
	Action        string `json:"action"`
	Manager       string `json:"manager"`
	Trigger       string `json:"trigger"`
	Configured    bool   `json:"configured"`
	Enabled       bool   `json:"enabled"`
	Changed       bool   `json:"changed"`
	Path          string `json:"path"`
	Notes         string `json:"notes"`
}

func runVMLifecycle(ctx context.Context, args []string, out io.Writer) error {
	return vmLifecycleCommand(ctx, args, runtime.GOOS, out)
}

func vmLifecycleCommand(ctx context.Context, args []string, goos string, out io.Writer) error {
	action := args[0]
	flags := args[1:]
	startupAction := "status"
	if action == "startup" && len(flags) > 0 && !strings.HasPrefix(flags[0], "-") {
		startupAction, flags = flags[0], flags[1:]
	}
	fs := flag.NewFlagSet("vm "+action, flag.ContinueOnError)
	name := fs.String("name", "", "local Multipass VM name (defaults to saved setup --vm)")
	asJSON, fail, err := reportFlags(fs, flags, out)
	if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	if action == "startup" && startupAction != "enable" && startupAction != "disable" && startupAction != "status" {
		return fail(errors.New("vm startup requires enable, disable or status"))
	}
	if *name == "" {
		cfg, err := loadConfig()
		if err != nil {
			return fail(fmt.Errorf("supply --name to select a local VM: %w", err))
		}
		*name = cfg.VM
	}
	if !vmLifecycleName.MatchString(*name) {
		return fail(errors.New("VM name must start with a letter, end with a letter or number, and contain only letters, numbers or hyphens; supply --name or setup --vm"))
	}
	if action == "startup" {
		r, err := configureVMStartup(ctx, *name, startupAction, goos)
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return json.NewEncoder(out).Encode(r)
		}
		fmt.Fprintf(out, "VM %s: next-login startup enabled=%t, configured=%t (%s)\n%s\n%s\n", r.Name, r.Enabled, r.Configured, r.Path, r.Notes, "Use vm start or vm stop to change the current VM state.")
		return nil
	}
	state, exists, err := localVMState(ctx, *name)
	if err != nil {
		return fail(err)
	}
	if !exists {
		return fail(fmt.Errorf("VM %s does not exist; inspect multipass list; no VM was created", *name))
	}
	r := vmLifecycleReport{SchemaVersion: 1, Name: *name, Action: action, State: state, Notes: vmLifecycleNotes}
	target := ""
	switch action {
	case "status":
	case "start":
		target = "Running"
		if state != "Running" && state != "Stopped" && state != "Suspended" {
			return fail(fmt.Errorf("cannot start VM %s in state %s; diagnose Multipass before retrying", *name, state))
		}
	case "stop":
		target = "Stopped"
		if state != "Running" && state != "Stopped" {
			return fail(fmt.Errorf("cannot safely stop VM %s in state %s; forced shutdown is not used", *name, state))
		}
	default:
		return fail(fmt.Errorf("unknown VM lifecycle action %q", action))
	}
	if target != "" && state != target {
		if action == "start" {
			if err = rejectPrimaryVM(ctx, *name); err != nil {
				return fail(err)
			}
		}
		bounded, cancel := context.WithTimeout(ctx, 6*time.Minute)
		defer cancel()
		commandArgs := []string{action, *name}
		if action == "start" {
			commandArgs = []string{"start", "--timeout", "300", *name}
		}
		if err = runProcess(bounded, "multipass", commandArgs, nil, io.Discard, io.Discard); err != nil {
			return fail(fmt.Errorf("multipass %s failed; inspect vm status before retrying because the operation may continue: %w", action, err))
		}
		r.Changed = true
		r.State, exists, err = localVMState(ctx, *name)
		if err != nil {
			return fail(fmt.Errorf("%s requested but final VM state is unavailable: %w", action, err))
		}
		if !exists || r.State != target {
			return fail(fmt.Errorf("%s requested but VM %s has state %q; expected %s", action, *name, r.State, target))
		}
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(r)
	}
	fmt.Fprintf(out, "Local VM: %s (%s); changed=%t\n%s\n", r.Name, r.State, r.Changed, r.Notes)
	return nil
}

func rejectPrimaryVM(ctx context.Context, name string) error {
	primary, err := multipassCapture(ctx, "get", "client.primary-name")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(primary)) == name {
		return errors.New("refusing the Multipass primary VM: start can create it if missing; use an existing named worker that is not client.primary-name")
	}
	return nil
}

type vmStartupEnv struct {
	home, executable, path string
	uid                    int
}

var vmStartupEnvironment = func() (vmStartupEnv, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return vmStartupEnv{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return vmStartupEnv{}, err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return vmStartupEnv{}, err
	}
	return vmStartupEnv{home: home, executable: exe, uid: os.Geteuid()}, nil
}
var vmStartupLookPath = exec.LookPath

func configureVMStartup(ctx context.Context, name, action, goos string) (vmStartupReport, error) {
	r := vmStartupReport{SchemaVersion: 1, Name: name, Action: action, Manager: "launchd", Trigger: "login", Notes: vmStartupNotes}
	if goos != "darwin" {
		if goos == "windows" {
			return r, errors.New("Windows VM automatic startup is not implemented or runtime-qualified; install and validate current Multipass with Virtual Machine Platform and an existing enrolled Linux worker first. Use vm start/stop/status manually; a user-logon Task Scheduler integration still needs native Windows validation")
		}
		return r, errors.New("vm startup supports macOS user login only; for native Linux Connect machine-boot services use host startup")
	}
	env, err := vmStartupEnvironment()
	if err != nil {
		return r, err
	}
	if env.uid == 0 {
		return r, errors.New("configure VM login startup as the desktop user, without sudo")
	}
	label := "cloud.deepai.connect.vm." + name
	r.Path = filepath.Join(env.home, "Library", "LaunchAgents", label+".plist")
	var unlock func()
	if action != "status" {
		unlock, err = platform.Lock(filepath.Join(env.home, ".config", "deepai-connect", "vm-startup"))
		if err != nil {
			return r, err
		}
		defer unlock()
	}
	existing, err := platform.ReadFile(r.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return r, err
	}
	r.Configured = err == nil
	if r.Configured {
		if !ownedVMStartup(existing, name) {
			return r, fmt.Errorf("startup file differs from Connect's managed format; preserve and inspect %s", r.Path)
		}
	}
	if action == "disable" {
		if !r.Configured {
			return r, nil
		}
		// Only remove our next-login file. Never unload a running VM, kill a launch
		// process, or change another component's startup configuration.
		if err = platform.CheckPath(r.Path); err != nil {
			return r, err
		}
		if err = os.Remove(r.Path); err != nil {
			return r, err
		}
		r.Configured, r.Changed = false, true
		return r, nil
	}
	if action == "status" {
		if !r.Configured {
			return r, nil
		}
		disabled, err := vmLaunchDisabled(ctx, env.uid, label)
		if err != nil {
			return r, err
		}
		r.Enabled = !disabled
		return r, nil
	}
	state, exists, err := localVMState(ctx, name)
	if err != nil {
		return r, err
	}
	if !exists || state == "Deleted" {
		return r, fmt.Errorf("VM %s must already exist; startup never creates or enrolls a worker", name)
	}
	if err = rejectPrimaryVM(ctx, name); err != nil {
		return r, err
	}
	if !filepath.IsAbs(env.executable) || strings.ContainsAny(env.executable, "\x00\r\n") {
		return r, errors.New("startup requires an absolute installed Connect executable path")
	}
	// A go-run/test temporary executable disappears after this session. Require a
	// stable install, not a login entry pointing to temporary build output.
	for _, root := range []string{os.TempDir(), "/tmp", "/var/tmp"} {
		temp, err := filepath.EvalSymlinks(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return r, err
		}
		if rel, err := filepath.Rel(temp, env.executable); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return r, errors.New("install Connect to a stable bin directory before enabling login startup; temporary executables are refused")
		}
	}
	multipass, err := vmStartupLookPath("multipass")
	if err != nil {
		return r, errors.New("install Multipass and make its CLI available before enabling VM startup")
	}
	multipass, err = filepath.Abs(multipass)
	if err != nil {
		return r, err
	}
	if strings.ContainsAny(multipass, ":\x00\r\n") {
		return r, errors.New("Multipass executable path cannot contain a colon or line break")
	}
	env.path = filepath.Dir(multipass) + ":/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	wanted := renderVMStartup(name, env.executable, env.path)
	if r.Configured && !bytes.Equal(existing, wanted) {
		return r, errors.New("startup executable or PATH changed; disable the existing VM startup entry before enabling its replacement")
	}
	disabled, err := vmLaunchDisabled(ctx, env.uid, label)
	if err != nil {
		return r, err
	}
	if !r.Configured {
		if err = platform.WriteFile(r.Path, wanted, true); err != nil {
			return r, err
		}
		r.Changed = true
	}
	if disabled {
		bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err = runProcess(bounded, "launchctl", []string{"enable", "gui/" + strconv.Itoa(env.uid) + "/" + label}, nil, io.Discard, io.Discard); err != nil {
			if !r.Configured {
				if rollbackErr := os.Remove(r.Path); rollbackErr != nil {
					return r, fmt.Errorf("enable failed and startup file rollback failed (%s): %w", r.Path, rollbackErr)
				}
			}
			return r, fmt.Errorf("enable next-login launchd entry: %w", err)
		}
		r.Changed = true
	}
	r.Configured, r.Enabled = true, true
	return r, nil
}

func vmLaunchDisabled(ctx context.Context, uid int, label string) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := runProcess(bounded, "launchctl", []string{"print-disabled", "gui/" + strconv.Itoa(uid)}, nil, &out, io.Discard); err != nil {
		return false, fmt.Errorf("read login startup overrides in the desktop user's GUI session: %w", err)
	}
	text := strings.TrimSpace(out.String())
	if !strings.HasPrefix(text, "disabled services = {") || !strings.HasSuffix(text, "}") {
		return false, errors.New("unrecognized launchctl startup override response")
	}
	entries := regexp.MustCompile(`(?m)^\s*"`+regexp.QuoteMeta(label)+`"\s*=>\s*(.*?)\s*$`).FindAllStringSubmatch(text, -1)
	if len(entries) == 0 {
		return false, nil
	}
	if len(entries) != 1 || entries[0][1] != "true" && entries[0][1] != "false" {
		return false, errors.New("unrecognized launchctl override for this VM")
	}
	return entries[0][1] == "true", nil
}

func xmlVMString(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func renderVMStartup(name, executable, path string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Managed by DeepAI Connect VM startup v1. -->
<plist version="1.0"><dict>
<key>Label</key><string>cloud.deepai.connect.vm.` + xmlVMString(name) + `</string>
<key>ProgramArguments</key><array><string>` + xmlVMString(executable) + `</string><string>vm</string><string>start</string><string>--name</string><string>` + xmlVMString(name) + `</string><string>--json</string></array>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>` + xmlVMString(path) + `</string></dict>
<key>RunAtLoad</key><true/>
<key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
`)
}

// Exact reconstruction protects user-edited/foreign files, while allowing safe
// removal after Connect or Multipass moved or was removed.
func ownedVMStartup(data []byte, name string) bool {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var values []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "string" {
			var value string
			if decoder.DecodeElement(&value, &start) != nil {
				return false
			}
			values = append(values, value)
		}
	}
	return len(values) == 9 && bytes.Equal(data, renderVMStartup(name, values[1], values[7]))
}
