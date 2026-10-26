package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const vmHelp = `Usage: deepai-connect vm start|stop|status [--name NAME] [--json]
       deepai-connect vm startup enable|disable|status [--name NAME] [--json]
       deepai-connect vm resources [--name NAME] [--json]
       deepai-connect vm configure --cpus N --memory SIZE --disk SIZE [--name NAME] [--apply]
       deepai-connect vm create --name NAME --cpus N --memory SIZE --disk SIZE [--apply]

Start/stop changes the existing VM now; it never creates or re-enrolls a worker.
Stop interrupts that VM's workloads. Status reports VM state, not cluster health.
Mac startup controls only the next user-login trigger, never the running VM.
Multipass may independently restore VMs when its daemon starts at machine boot.
Disable this startup entry before uninstalling the referenced Connect binary.
Windows automatic startup remains unimplemented and runtime-unqualified.

Inspect or grant a local Multipass VM's CPU, RAM and virtual disk budget.
The saved setup --vm name is used unless --name is supplied; no hub is required
with an explicit name. Resource inspection does not depend on guest SSH.

Configure and create show a preview by default. Add --apply to make changes.
Configure requires a Stopped VM and never stops, starts or recreates it.
Disk sizes can only grow. Create launches Ubuntu 24.04 with the chosen budget;
installing Connect/K3s and enrolling the worker remain separate steps.

Sizes use Multipass binary units: 1G = 1GiB; K/KB/KiB, M/MB/MiB and G/GB/GiB
are accepted. Minimum memory is 512M; minimum disk is 1G.
vCPUs share host execution time. Guest OS/K3s consume part of the VM RAM budget;
host hypervisor overhead is additional.
The virtual disk limit does not reserve physical disk space on the host.

Examples:
  deepai-connect vm resources
  deepai-connect vm configure --cpus 4 --memory 8G --disk 20G
  deepai-connect vm create --name worker-2 --cpus 4 --memory 8G --disk 20G`

const vmResourceNotes = "vCPUs share host execution time; they are not dedicated cores. RAM is a guest budget, not locked host memory; guest OS/K3s consume part of it and host hypervisor overhead is additional. Virtual disk is a logical limit, not reserved host space; guest filesystems may be smaller. Host directory mounts use storage outside this virtual disk limit."

type vmGrant struct {
	CPUs        int    `json:"cpus"`
	MemoryBytes uint64 `json:"memoryBytes"`
	DiskBytes   uint64 `json:"diskBytes"`
}

type vmResourceReport struct {
	Name     string        `json:"name"`
	State    string        `json:"state"`
	Grant    vmGrant       `json:"grant"`
	Host     HostResources `json:"host"`
	Notes    string        `json:"notes"`
	Warnings []string      `json:"warnings,omitempty"`
}

var readVMHostResources = detectHostResources

func runVM(ctx context.Context, args []string) error {
	return runVMTo(ctx, args, os.Stdout)
}

func runVMTo(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || requestsHelp(args) {
		fmt.Fprintln(out, vmHelp)
		return nil
	}
	action := args[0]
	if action == "start" || action == "stop" || action == "status" || action == "startup" {
		return runVMLifecycle(ctx, args, out)
	}
	if action != "resources" && action != "configure" && action != "create" {
		return fmt.Errorf("unknown vm command %q; use start, stop, status, startup, resources, configure or create", action)
	}
	fs := flag.NewFlagSet("vm "+action, flag.ContinueOnError)
	fs.SetOutput(out)
	name := fs.String("name", "", "local Multipass VM name (defaults to saved setup --vm)")
	var asJSON, apply bool
	var cpus int
	var memory, disk string
	if action == "resources" {
		fs.BoolVar(&asJSON, "json", false, "print structured resource grants")
	} else {
		fs.IntVar(&cpus, "cpus", 0, "number of virtual CPUs")
		fs.StringVar(&memory, "memory", "", "VM memory budget, e.g. 8G")
		fs.StringVar(&disk, "disk", "", "VM virtual disk size, e.g. 20G")
		fs.BoolVar(&apply, "apply", false, "apply the previewed resource grant")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *name == "" {
		if action == "create" {
			return errors.New("vm create requires --name")
		}
		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("supply --name to select a local VM: %w", err)
		}
		*name = cfg.VM
	}
	if !regexp.MustCompile(`^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`).MatchString(*name) {
		return errors.New("VM name must start with a letter, end with a letter or number, and contain only letters, numbers or hyphens; supply --name or setup --vm")
	}
	var desired vmGrant
	if action != "resources" {
		var err error
		desired, err = validateVMGrant(cpus, memory, disk)
		if err != nil {
			return err
		}
	}
	state, exists, err := localVMState(ctx, *name)
	if err != nil {
		return err
	}
	if action == "create" {
		if exists {
			return fmt.Errorf("VM %s already exists (%s); use vm configure to preserve its identity", *name, state)
		}
		return createVM(ctx, *name, desired, apply, out)
	}
	if !exists {
		return fmt.Errorf("VM %s does not exist; inspect multipass list or use vm create", *name)
	}
	current, err := readVMGrant(ctx, *name)
	if err != nil {
		return err
	}
	host := readVMHostResources(ctx)
	if action == "resources" {
		r := vmResourceReport{Name: *name, State: state, Grant: current, Host: host, Notes: vmResourceNotes, Warnings: vmHostWarnings(host, current, 0)}
		if asJSON {
			encoder := json.NewEncoder(out)
			encoder.SetIndent("", "  ")
			return encoder.Encode(r)
		}
		fmt.Fprintf(out, "Local VM: %s (%s)\n", *name, state)
		printVMGrant(out, "Configured", current)
		printVMHost(out, host, r.Warnings)
		fmt.Fprintln(out, "\n"+vmResourceNotes)
		return nil
	}
	if desired.DiskBytes < current.DiskBytes {
		return fmt.Errorf("cannot shrink virtual disk from %d to %d bytes; no settings changed", current.DiskBytes, desired.DiskBytes)
	}
	fmt.Fprintf(out, "VM resource plan: %s (%s)\n", *name, state)
	printVMGrant(out, "Current", current)
	printVMGrant(out, "Requested", desired)
	printVMHost(out, host, vmHostWarnings(host, desired, desired.DiskBytes-current.DiskBytes))
	fmt.Fprintln(out, "\n"+vmResourceNotes)
	if !apply {
		fmt.Fprintln(out, "\nPreview only; no settings changed. Add --apply when the VM is stopped.")
		fmt.Fprintf(out, "Stop first: multipass stop %s\nStart after applying: multipass start %s\n", *name, *name)
		return nil
	}
	if state != "Stopped" {
		return fmt.Errorf("VM %s is %s; no settings changed; stop it with multipass stop %s, apply again, then multipass start %s", *name, state, *name, *name)
	}
	return configureVM(ctx, *name, current, desired, out)
}

func validateVMGrant(cpus int, memory, disk string) (vmGrant, error) {
	grant := vmGrant{CPUs: cpus}
	if cpus < 1 || cpus > 2147483647 || memory == "" || disk == "" {
		return grant, errors.New("specify all of --cpus (positive integer), --memory and --disk")
	}
	var err error
	if grant.MemoryBytes, err = parseMultipassSize(memory); err != nil {
		return grant, fmt.Errorf("invalid --memory: %w", err)
	}
	if grant.DiskBytes, err = parseMultipassSize(disk); err != nil {
		return grant, fmt.Errorf("invalid --disk: %w", err)
	}
	if grant.MemoryBytes < 512<<20 || grant.DiskBytes < 1<<30 {
		return grant, errors.New("VM memory must be at least 512M and disk at least 1G")
	}
	return grant, nil
}

var multipassSizePattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([A-Za-z]*)$`)

// Multipass uses binary units even for KB/MB/GB and floors fractional units.
// Exact arithmetic matters here: rounding a disk size up could permit a shrink.
func parseMultipassSize(value string) (uint64, error) {
	parts := multipassSizePattern.FindStringSubmatch(strings.TrimSpace(value))
	if parts == nil {
		return 0, fmt.Errorf("%q is not a positive size (e.g. 8G)", value)
	}
	units := map[string]int64{"": 1, "B": 1, "K": 1 << 10, "KB": 1 << 10, "KIB": 1 << 10, "M": 1 << 20, "MB": 1 << 20, "MIB": 1 << 20, "G": 1 << 30, "GB": 1 << 30, "GIB": 1 << 30}
	factor, ok := units[strings.ToUpper(parts[2])]
	if !ok || factor == 1 && strings.Contains(parts[1], ".") {
		return 0, fmt.Errorf("%q requires integer bytes or K/KB/KiB, M/MB/MiB, G/GB/GiB units", value)
	}
	number, ok := new(big.Rat).SetString(parts[1])
	if !ok {
		return 0, fmt.Errorf("%q is not a valid size", value)
	}
	number.Mul(number, big.NewRat(factor, 1))
	integer := new(big.Int).Quo(number.Num(), number.Denom())
	if integer.Sign() <= 0 || !integer.IsInt64() {
		return 0, fmt.Errorf("%q is outside the supported positive size range", value)
	}
	return integer.Uint64(), nil
}

func multipassCapture(ctx context.Context, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := runProcess(bounded, "multipass", args, nil, &out, io.Discard); err != nil {
		return nil, fmt.Errorf("multipass %s failed; check the local Multipass service: %w", args[0], err)
	}
	return out.Bytes(), nil
}

// list and get query the daemon; info can hang trying to contact a broken guest.
func localVMState(ctx context.Context, name string) (string, bool, error) {
	data, err := multipassCapture(ctx, "list", "--format", "json")
	if err != nil {
		return "", false, err
	}
	var result struct {
		List []struct{ Name, State string } `json:"list"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.List == nil {
		return "", false, errors.New("invalid Multipass list response")
	}
	for _, instance := range result.List {
		if instance.Name == name {
			if instance.State == "" {
				return "", false, errors.New("Multipass returned an empty VM state")
			}
			return instance.State, true, nil
		}
	}
	return "", false, nil
}

func readVMGrant(ctx context.Context, name string) (vmGrant, error) {
	var g vmGrant
	values := make([]string, 3)
	for i, key := range []string{"cpus", "memory", "disk"} {
		data, err := multipassCapture(ctx, "get", "local."+name+"."+key)
		if err != nil {
			return g, err
		}
		values[i] = strings.TrimSpace(string(data))
	}
	var err error
	if g.CPUs, err = strconv.Atoi(values[0]); err != nil || g.CPUs < 1 {
		return g, errors.New("Multipass returned an invalid CPU grant")
	}
	if g.MemoryBytes, err = parseMultipassSize(values[1]); err != nil {
		return g, fmt.Errorf("invalid Multipass memory grant: %w", err)
	}
	if g.DiskBytes, err = parseMultipassSize(values[2]); err != nil {
		return g, fmt.Errorf("invalid Multipass disk grant: %w", err)
	}
	return g, nil
}

func configureVM(ctx context.Context, name string, current, desired vmGrant, out io.Writer) error {
	settings := []struct {
		key     string
		old, to uint64
	}{
		{"cpus", uint64(current.CPUs), uint64(desired.CPUs)},
		{"memory", current.MemoryBytes, desired.MemoryBytes},
		// Grow the disk last because it cannot be rolled back safely.
		{"disk", current.DiskBytes, desired.DiskBytes},
	}
	var applied []string
	for _, setting := range settings {
		if setting.old == setting.to {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, time.Minute)
		err := runProcess(bounded, "multipass", []string{"set", "local." + name + "." + setting.key + "=" + strconv.FormatUint(setting.to, 10)}, nil, out, io.Discard)
		cancel()
		if err != nil {
			confirmed := "none"
			if len(applied) > 0 {
				confirmed = strings.Join(applied, ", ")
			}
			return fmt.Errorf("VM resource update incomplete: confirmed settings changed: %s; %s failed (%w) and its outcome may be uncertain; no rollback or restart attempted; inspect deepai-connect vm resources --name %s before retrying", confirmed, setting.key, err, name)
		}
		applied = append(applied, setting.key)
	}
	fmt.Fprintf(out, "\nResource grant applied; VM remains stopped. Start it with multipass start %s\n", name)
	if desired.DiskBytes > current.DiskBytes {
		fmt.Fprintln(out, "After starting, check the guest filesystem grew to use the expanded virtual disk.")
	}
	return nil
}

func createVM(ctx context.Context, name string, desired vmGrant, apply bool, out io.Writer) error {
	// Multipass automatically mounts the host home into its primary instance.
	primary, err := multipassCapture(ctx, "get", "client.primary-name")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(primary)) == name {
		return errors.New("choose a VM name other than the Multipass primary name; primary automatically mounts the host home directory outside the VM disk budget")
	}
	fmt.Fprintf(out, "Create VM plan: %s (Ubuntu 24.04)\n", name)
	printVMGrant(out, "Requested", desired)
	host := readVMHostResources(ctx)
	printVMHost(out, host, vmHostWarnings(host, desired, desired.DiskBytes))
	fmt.Fprintln(out, "\n"+vmResourceNotes)
	if !apply {
		fmt.Fprintln(out, "\nPreview only; no VM created. Add --apply to create and start this VM.")
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	args := []string{"launch", "24.04", "--name", name, "--cpus", strconv.Itoa(desired.CPUs), "--memory", strconv.FormatUint(desired.MemoryBytes, 10), "--disk", strconv.FormatUint(desired.DiskBytes, 10), "--timeout", "300"}
	if err := runProcess(bounded, "multipass", args, nil, out, os.Stderr); err != nil {
		return fmt.Errorf("VM creation did not finish successfully: %w; Multipass may still have created %s; inspect multipass list before retrying; no VM was deleted", err, name)
	}
	fmt.Fprintln(out, "\nVM created with the requested budget. Install Connect/K3s and enroll it as a worker to provide cluster compute.")
	return nil
}

func vmSize(n uint64) string { return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30)) }

func printVMGrant(out io.Writer, label string, g vmGrant) {
	fmt.Fprintf(out, "%s: %d vCPU · %s RAM · %s virtual disk\n", label, g.CPUs, vmSize(g.MemoryBytes), vmSize(g.DiskBytes))
}

func printVMHost(out io.Writer, host HostResources, warnings []string) {
	fmt.Fprintf(out, "Host: %d logical CPUs", host.CPUs)
	if host.MemoryBytes != nil {
		fmt.Fprintf(out, " · %s physical RAM", vmSize(*host.MemoryBytes))
	}
	if host.StorageAvailableBytes != nil {
		fmt.Fprintf(out, " · %s available on %s", vmSize(*host.StorageAvailableBytes), host.StoragePath)
	}
	fmt.Fprintln(out, "\nHost figures are advisory; Multipass backing storage may be on another volume.")
	for _, warning := range warnings {
		fmt.Fprintln(out, "Warning: "+warning)
	}
}

func vmHostWarnings(host HostResources, desired vmGrant, diskGrowth uint64) []string {
	warnings := append([]string(nil), host.Warnings...)
	if desired.CPUs >= host.CPUs && host.CPUs > 0 {
		warnings = append(warnings, "the VM can occupy all host CPU threads; leave capacity for your desktop and other VMs.")
	}
	if host.MemoryBytes != nil && desired.MemoryBytes >= *host.MemoryBytes {
		warnings = append(warnings, "the requested memory reaches or exceeds physical host RAM; reduce it to leave memory for the host and other VMs.")
	}
	if host.StorageAvailableBytes != nil && diskGrowth > *host.StorageAvailableBytes {
		warnings = append(warnings, fmt.Sprintf("requested disk growth (%s) exceeds currently available host space on %s (%s); free space or verify a different backing volume before applying. Sparse allocation does not guarantee that the VM can fill its disk.", vmSize(diskGrowth), host.StoragePath, vmSize(*host.StorageAvailableBytes)))
	} else if diskGrowth > 0 {
		warnings = append(warnings, "verify free space on the actual Multipass backing volume before applying; disk growth and snapshots consume host space over time.")
	}
	return warnings
}
