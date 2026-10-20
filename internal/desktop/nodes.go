package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const nodesHelp = `Usage: deepai-connect nodes [--details | --json]

One row per node: status, CPU, memory and local disk capacity, with usage percentages.
CPU% and MEM% use total node capacity; DISK% uses the local filesystem capacity.
Missing or stale usage is <unknown>. Mac workers show their VM's resources.

  --details  Include resource budgets, storage and diagnostics
  --json     Print the structured resource report

For native Kubernetes output: deepai-connect kubectl get nodes -o wide
`

// Pointer fields distinguish unknown observations from a measured zero. Byte
// quantities use float64 because the Kubernetes quantity grammar allows fractions.
type resourceAmounts struct {
	CPUCores              *float64 `json:"cpuCores"`
	MemoryBytes           *float64 `json:"memoryBytes"`
	EphemeralStorageBytes *float64 `json:"ephemeralStorageBytes"`
}

type resourceUsage struct {
	CPUCores              *float64   `json:"cpuCores"`
	MemoryWorkingSetBytes *float64   `json:"memoryWorkingSetBytes"`
	CPUObservedAt         *time.Time `json:"cpuObservedAt"`
	MemoryObservedAt      *time.Time `json:"memoryObservedAt"`
	CPUSource             string     `json:"cpuSource"`
	MemorySource          string     `json:"memorySource"`
}

type resourceFilesystem struct {
	CapacityBytes  *float64   `json:"capacityBytes"`
	UsedBytes      *float64   `json:"usedBytes"`
	AvailableBytes *float64   `json:"availableBytes"`
	ObservedAt     *time.Time `json:"observedAt"`
}

type resourceNode struct {
	Name               string             `json:"name"`
	Architecture       string             `json:"architecture"`
	Ready              string             `json:"ready"`
	LastHeartbeatAt    *time.Time         `json:"lastHeartbeatAt"`
	CapacityMayBeStale bool               `json:"capacityMayBeStale"`
	Capacity           resourceAmounts    `json:"capacity"`
	Allocatable        resourceAmounts    `json:"allocatable"`
	Usage              resourceUsage      `json:"usage"`
	Filesystem         resourceFilesystem `json:"filesystem"`
	ImageFilesystem    resourceFilesystem `json:"imageFilesystem"`
	Warnings           []string           `json:"warnings"`
}

type persistentResource struct {
	Kind           string   `json:"kind"`
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace,omitempty"`
	StorageClass   string   `json:"storageClass"`
	Phase          string   `json:"phase"`
	RequestedBytes *float64 `json:"requestedBytes"`
	CapacityBytes  *float64 `json:"capacityBytes"`
	VolumeName     string   `json:"volumeName,omitempty"`
}

type persistentResources struct {
	Scope     string               `json:"scope"`
	Available bool                 `json:"available"`
	Volumes   []persistentResource `json:"volumes"`
	Claims    []persistentResource `json:"claims"`
}

type resourcesReport struct {
	SchemaVersion int                 `json:"schemaVersion"`
	ObservedAt    time.Time           `json:"observedAt"`
	Hub           string              `json:"hub"`
	Nodes         []resourceNode      `json:"nodes"`
	Storage       persistentResources `json:"persistentStorage"`
	Warnings      []string            `json:"warnings"`
}

func runNodes(ctx context.Context, args []string) error {
	return nodesCommand(ctx, args, os.Stdout)
}

func nodesCommand(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("nodes", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), nodesHelp) }
	asJSON := fs.Bool("json", false, "structured output")
	details := fs.Bool("details", false, "show the full resource report")
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
		for _, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "--json" || arg == "--json=true" {
				*asJSON = true
			}
			if arg == "--json=false" {
				*asJSON = false
			}
		}
		return fail(err)
	}
	if fs.NArg() != 0 {
		return fail(errors.New("nodes shows all nodes; use --details or --json"))
	}
	if *details && *asJSON {
		return fail(errors.New("choose --details or JSON output, not both"))
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	report, err := collectResources(ctx, cfg)
	if err != nil {
		return fail(err)
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(report)
	}
	if *details {
		printResourceDetails(out, report)
	} else {
		printResources(out, report)
	}
	return nil
}

// All SSH probes have a wall-clock bound in addition to kubectl's request limit.
func captureResources(ctx context.Context, cfg Config, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	return captureKube(ctx, cfg, args...)
}

type nodeResourcesAPI struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Capacity    map[string]string `json:"capacity"`
			Allocatable map[string]string `json:"allocatable"`
			NodeInfo    struct {
				Architecture string `json:"architecture"`
			} `json:"nodeInfo"`
			Conditions []struct {
				Type              string     `json:"type"`
				Status            string     `json:"status"`
				LastHeartbeatTime *time.Time `json:"lastHeartbeatTime"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

type metricsResourcesAPI struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Timestamp *time.Time        `json:"timestamp"`
		Usage     map[string]string `json:"usage"`
	} `json:"items"`
}

func collectResources(ctx context.Context, cfg Config) (*resourcesReport, error) {
	data, err := captureResources(ctx, cfg, "get", "nodes", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("cannot read node capacities over SSH: %w", err)
	}
	var nodes nodeResourcesAPI
	if err := json.Unmarshal(data, &nodes); err != nil || nodes.Items == nil {
		return nil, errors.New("hub returned an invalid node list")
	}
	r := &resourcesReport{SchemaVersion: 1, ObservedAt: time.Now().UTC(), Hub: cfg.Hub, Nodes: []resourceNode{}, Warnings: []string{}, Storage: persistentResources{Scope: "cluster", Volumes: []persistentResource{}, Claims: []persistentResource{}}}
	for _, item := range nodes.Items {
		n := resourceNode{Name: item.Metadata.Name, Architecture: item.Status.NodeInfo.Architecture, Ready: "Unknown", Warnings: []string{}}
		n.Capacity = parseResourceAmounts(item.Status.Capacity, "capacity", &n.Warnings)
		n.Allocatable = parseResourceAmounts(item.Status.Allocatable, "allocatable", &n.Warnings)
		for _, c := range item.Status.Conditions {
			if c.Type == "Ready" {
				n.Ready, n.LastHeartbeatAt = c.Status, c.LastHeartbeatTime
			}
		}
		n.CapacityMayBeStale = n.Ready != "True"
		if n.CapacityMayBeStale {
			n.Warnings = append(n.Warnings, "node is not Ready; capacities are last reported and may be stale")
		}
		r.Nodes = append(r.Nodes, n)
	}
	sort.Slice(r.Nodes, func(i, j int) bool { return r.Nodes[i].Name < r.Nodes[j].Name })

	// Each job writes to independent storage. Merge metrics only after all probes
	// finish, so kubelet measurements take precedence without races.
	var metrics metricsResourcesAPI
	var metricsErr, storageErr error
	jobs := []func(){
		func() {
			data, err := captureResources(ctx, cfg, "get", "--raw=/apis/metrics.k8s.io/v1beta1/nodes")
			if err != nil {
				metricsErr = err
				return
			}
			if err = json.Unmarshal(data, &metrics); err != nil || metrics.Items == nil {
				metricsErr = errors.New("invalid metrics response")
			}
		},
		func() {
			data, err := captureResources(ctx, cfg, "get", "pv,pvc", "--all-namespaces", "-o", "json")
			if err != nil {
				storageErr = err
				return
			}
			storageErr = parsePersistentResources(data, &r.Storage)
		},
	}
	for i := range r.Nodes {
		n := &r.Nodes[i]
		jobs = append(jobs, func() {
			data, err := captureResources(ctx, cfg, "get", "--raw=/api/v1/nodes/"+url.PathEscape(n.Name)+"/proxy/stats/summary")
			if err == nil {
				err = applyResourceSummary(data, n)
			}
			if err != nil {
				n.Warnings = append(n.Warnings, "kubelet statistics unavailable; live usage and local disk may be unknown")
			}
		})
	}
	queue := make(chan func(), len(jobs))
	for _, job := range jobs {
		queue <- job
	}
	close(queue)
	var wg sync.WaitGroup
	for range min(4, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range queue {
				job()
			}
		}()
	}
	wg.Wait()
	if metricsErr != nil {
		metrics.Items = nil
		r.Warnings = append(r.Warnings, "metrics API unavailable; using kubelet measurements where available")
	}
	if storageErr != nil {
		r.Warnings = append(r.Warnings, "persistent volume and claim inventory unavailable")
	}
	for i := range r.Nodes {
		n := &r.Nodes[i]
		for _, m := range metrics.Items {
			if m.Metadata.Name != n.Name {
				continue
			}
			if n.Usage.CPUCores == nil {
				n.Usage.CPUCores = resourceQuantity(m.Usage["cpu"], "CPU usage", &n.Warnings)
				if n.Usage.CPUCores != nil {
					n.Usage.CPUObservedAt, n.Usage.CPUSource = m.Timestamp, "metrics.k8s.io"
				}
			}
			if n.Usage.MemoryWorkingSetBytes == nil {
				n.Usage.MemoryWorkingSetBytes = resourceQuantity(m.Usage["memory"], "memory usage", &n.Warnings)
				if n.Usage.MemoryWorkingSetBytes != nil {
					n.Usage.MemoryObservedAt, n.Usage.MemorySource = m.Timestamp, "metrics.k8s.io"
				}
			}
		}
		if n.Usage.CPUCores == nil || n.Usage.MemoryWorkingSetBytes == nil {
			n.Warnings = append(n.Warnings, "some live CPU/memory measurements are unavailable")
		}
		for label, at := range map[string]*time.Time{"CPU": n.Usage.CPUObservedAt, "memory": n.Usage.MemoryObservedAt, "filesystem": n.Filesystem.ObservedAt} {
			if at != nil && r.ObservedAt.Sub(*at) > 5*time.Minute {
				n.Warnings = append(n.Warnings, label+" measurement is over 5 minutes old")
			}
		}
		sort.Strings(n.Warnings)
	}
	return r, nil
}

var resourceQuantityPattern = regexp.MustCompile(`^([+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))([eE][+-]?[0-9]+|[numkMGTPE]|[KMGTPE]i)?$`)

func parseResourceQuantity(s string) (float64, error) {
	m := resourceQuantityPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid nonnegative resource quantity %q", s)
	}
	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	multipliers := map[string]float64{"": 1, "n": 1e-9, "u": 1e-6, "m": 1e-3, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60}
	if multiplier, ok := multipliers[m[2]]; ok {
		value *= multiplier
	} else {
		value, err = strconv.ParseFloat(m[1]+m[2], 64)
	}
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, errors.New("resource quantity exceeds supported range")
	}
	return value, nil
}

func resourceQuantity(s, label string, warnings *[]string) *float64 {
	if s == "" {
		return nil
	}
	v, err := parseResourceQuantity(s)
	if err != nil {
		*warnings = append(*warnings, label+" has an invalid quantity")
		return nil
	}
	return &v
}

func parseResourceAmounts(values map[string]string, label string, warnings *[]string) resourceAmounts {
	return resourceAmounts{
		CPUCores:              resourceQuantity(values["cpu"], label+" CPU", warnings),
		MemoryBytes:           resourceQuantity(values["memory"], label+" memory", warnings),
		EphemeralStorageBytes: resourceQuantity(values["ephemeral-storage"], label+" ephemeral storage", warnings),
	}
}

func applyResourceSummary(data []byte, n *resourceNode) error {
	type fsStats struct {
		Time           *time.Time `json:"time"`
		CapacityBytes  *float64   `json:"capacityBytes"`
		UsedBytes      *float64   `json:"usedBytes"`
		AvailableBytes *float64   `json:"availableBytes"`
	}
	var summary struct {
		Node struct {
			Name string `json:"nodeName"`
			CPU  struct {
				Time           *time.Time `json:"time"`
				UsageNanoCores *float64   `json:"usageNanoCores"`
			} `json:"cpu"`
			Memory struct {
				Time            *time.Time `json:"time"`
				WorkingSetBytes *float64   `json:"workingSetBytes"`
			} `json:"memory"`
			FS      fsStats `json:"fs"`
			Runtime struct {
				ImageFS fsStats `json:"imageFs"`
			} `json:"runtime"`
		} `json:"node"`
	}
	if err := json.Unmarshal(data, &summary); err != nil {
		return err
	}
	if summary.Node.Name != n.Name {
		return errors.New("kubelet response has a different or absent node name")
	}
	cpu, memory := summary.Node.CPU, summary.Node.Memory
	if cpu.UsageNanoCores != nil && *cpu.UsageNanoCores >= 0 {
		cores := *cpu.UsageNanoCores / 1e9
		n.Usage.CPUCores, n.Usage.CPUObservedAt, n.Usage.CPUSource = &cores, cpu.Time, "kubelet"
	}
	if memory.WorkingSetBytes != nil && *memory.WorkingSetBytes >= 0 {
		n.Usage.MemoryWorkingSetBytes, n.Usage.MemoryObservedAt, n.Usage.MemorySource = memory.WorkingSetBytes, memory.Time, "kubelet"
	}
	convertFS := func(fs fsStats) resourceFilesystem {
		nonnegative := func(p *float64) *float64 {
			if p != nil && *p < 0 {
				return nil
			}
			return p
		}
		return resourceFilesystem{nonnegative(fs.CapacityBytes), nonnegative(fs.UsedBytes), nonnegative(fs.AvailableBytes), fs.Time}
	}
	n.Filesystem, n.ImageFilesystem = convertFS(summary.Node.FS), convertFS(summary.Node.Runtime.ImageFS)
	if n.Filesystem.CapacityBytes == nil || n.Filesystem.UsedBytes == nil || n.Filesystem.AvailableBytes == nil {
		n.Warnings = append(n.Warnings, "some local filesystem measurements are unavailable")
	}
	return nil
}

func parsePersistentResources(data []byte, storage *persistentResources) error {
	var list struct {
		Items []struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				StorageClassName string            `json:"storageClassName"`
				VolumeName       string            `json:"volumeName"`
				Capacity         map[string]string `json:"capacity"`
				Resources        struct {
					Requests map[string]string `json:"requests"`
				} `json:"resources"`
			} `json:"spec"`
			Status struct {
				Phase    string            `json:"phase"`
				Capacity map[string]string `json:"capacity"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	if list.Items == nil {
		return errors.New("invalid persistent storage list")
	}
	volumes, claims := []persistentResource{}, []persistentResource{}
	for _, item := range list.Items {
		warnings := []string{}
		v := persistentResource{Kind: item.Kind, Name: item.Metadata.Name, Namespace: item.Metadata.Namespace, StorageClass: item.Spec.StorageClassName, Phase: item.Status.Phase, VolumeName: item.Spec.VolumeName}
		switch item.Kind {
		case "PersistentVolume":
			v.CapacityBytes = resourceQuantity(item.Spec.Capacity["storage"], "volume capacity", &warnings)
			volumes = append(volumes, v)
		case "PersistentVolumeClaim":
			v.RequestedBytes = resourceQuantity(item.Spec.Resources.Requests["storage"], "claim request", &warnings)
			v.CapacityBytes = resourceQuantity(item.Status.Capacity["storage"], "claim capacity", &warnings)
			claims = append(claims, v)
		default:
			return fmt.Errorf("unexpected persistent storage kind %q", item.Kind)
		}
		if len(warnings) != 0 {
			return errors.New("invalid persistent storage quantity")
		}
	}
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Name < volumes[j].Name })
	sort.Slice(claims, func(i, j int) bool {
		return claims[i].Namespace+"/"+claims[i].Name < claims[j].Namespace+"/"+claims[j].Name
	})
	storage.Available, storage.Volumes, storage.Claims = true, volumes, claims
	return nil
}

func resourceNumber(value *float64, divisor float64) string {
	if value == nil {
		return "?"
	}
	return fmt.Sprintf("%.2f", *value/divisor)
}

func resourceTime(t *time.Time) string {
	if t == nil {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

func printResources(out io.Writer, r *resourcesReport) {
	if len(r.Nodes) == 0 {
		fmt.Fprintln(out, "No nodes found.")
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATUS\tCPU\tCPU%\tMEMORY\tMEM%\tDISK\tDISK%")
	for _, n := range r.Nodes {
		status := "Unknown"
		switch n.Ready {
		case "True":
			status = "Ready"
		case "False":
			status = "NotReady"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			displayNetworkName(n.Name), status, compactResourceNumber(n.Capacity.CPUCores, 1, ""),
			resourcePercent(n.Usage.CPUCores, n.Capacity.CPUCores, n.Usage.CPUObservedAt, r.ObservedAt),
			compactResourceBytes(n.Capacity.MemoryBytes),
			resourcePercent(n.Usage.MemoryWorkingSetBytes, n.Capacity.MemoryBytes, n.Usage.MemoryObservedAt, r.ObservedAt),
			compactResourceBytes(n.Filesystem.CapacityBytes),
			resourcePercent(n.Filesystem.UsedBytes, n.Filesystem.CapacityBytes, n.Filesystem.ObservedAt, r.ObservedAt))
	}
	_ = w.Flush()
}

func compactResourceNumber(value *float64, divisor float64, suffix string) string {
	if value == nil {
		return "<unknown>"
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", *value/divisor), "0"), ".") + suffix
}

func compactResourceBytes(value *float64) string {
	for _, unit := range []struct {
		divisor float64
		suffix  string
	}{{1 << 40, "Ti"}, {1 << 30, "Gi"}, {1 << 20, "Mi"}, {1 << 10, "Ki"}} {
		if value != nil && *value >= unit.divisor {
			return compactResourceNumber(value, unit.divisor, unit.suffix)
		}
	}
	return compactResourceNumber(value, 1, "B")
}

// The compact view has no diagnostics footer. Never show an old or undated
// measurement as current usage just because its numeric value is still cached.
func resourcePercent(used, capacity *float64, at *time.Time, now time.Time) string {
	if used == nil || capacity == nil || *capacity <= 0 || at == nil || at.IsZero() || now.Sub(*at) > 5*time.Minute || at.After(now.Add(time.Minute)) {
		return "<unknown>"
	}
	return fmt.Sprintf("%.0f%%", *used / *capacity * 100)
}

func printResourceDetails(out io.Writer, r *resourcesReport) {
	fmt.Fprintf(out, "Resources via %s · %s\n\n", displayNetworkName(r.Hub), r.ObservedAt.Format(time.RFC3339))
	const gib = 1 << 30
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tREADY\tCPU CAP\tCPU ALLOC\tCPU USED\tRAM CAP GiB\tRAM ALLOC\tRAM USED")
	for _, n := range r.Nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", displayNetworkName(n.Name), displayNetworkName(n.Ready), resourceNumber(n.Capacity.CPUCores, 1), resourceNumber(n.Allocatable.CPUCores, 1), resourceNumber(n.Usage.CPUCores, 1), resourceNumber(n.Capacity.MemoryBytes, gib), resourceNumber(n.Allocatable.MemoryBytes, gib), resourceNumber(n.Usage.MemoryWorkingSetBytes, gib))
	}
	_ = w.Flush()
	fmt.Fprintln(out, "\nLocal storage (GiB; each node has its own disk)")
	w = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tFILESYSTEM\tUSED\tAVAILABLE\tEPHEMERAL CAP\tEPHEMERAL ALLOC")
	for _, n := range r.Nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", displayNetworkName(n.Name), resourceNumber(n.Filesystem.CapacityBytes, gib), resourceNumber(n.Filesystem.UsedBytes, gib), resourceNumber(n.Filesystem.AvailableBytes, gib), resourceNumber(n.Capacity.EphemeralStorageBytes, gib), resourceNumber(n.Allocatable.EphemeralStorageBytes, gib))
	}
	_ = w.Flush()
	hasImageFilesystem := false
	for _, n := range r.Nodes {
		fs := n.ImageFilesystem
		hasImageFilesystem = hasImageFilesystem || fs.CapacityBytes != nil || fs.UsedBytes != nil || fs.AvailableBytes != nil
	}
	if hasImageFilesystem {
		fmt.Fprintln(out, "\nRuntime image filesystem (GiB)")
		w = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NODE\tCAPACITY\tUSED\tAVAILABLE")
		for _, n := range r.Nodes {
			fs := n.ImageFilesystem
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", displayNetworkName(n.Name), resourceNumber(fs.CapacityBytes, gib), resourceNumber(fs.UsedBytes, gib), resourceNumber(fs.AvailableBytes, gib))
		}
		_ = w.Flush()
	}
	fmt.Fprintln(out, "\nCPU is in cores; RAM usage is working set. ? = unknown.")
	fmt.Fprintln(out, "Allocatable is the pod budget, not current free CPU, memory or disk.")
	fmt.Fprintln(out, "A macOS worker reports the Linux VM allocation, not the whole Mac.")
	fmt.Fprintln(out, "Root and image filesystems can share a disk; they must not be added together.")
	fmt.Fprintln(out, "\nPersistent storage (cluster-wide)")
	if !r.Storage.Available {
		fmt.Fprintln(out, "Inventory unavailable.")
	} else if len(r.Storage.Volumes)+len(r.Storage.Claims) == 0 {
		fmt.Fprintln(out, "No persistent volumes or claims.")
	} else {
		w = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tNAME\tCLASS\tPHASE\tREQUEST GiB\tCAPACITY GiB")
		for _, group := range [][]persistentResource{r.Storage.Volumes, r.Storage.Claims} {
			for _, v := range group {
				name, kind := v.Name, "PV"
				if v.Namespace != "" {
					name, kind = v.Namespace+"/"+name, "PVC"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", kind, displayNetworkName(name), displayNetworkName(v.StorageClass), displayNetworkName(v.Phase), resourceNumber(v.RequestedBytes, gib), resourceNumber(v.CapacityBytes, gib))
			}
		}
		_ = w.Flush()
		fmt.Fprintln(out, "PV/PVC sizes are declared capacities, not usage or guaranteed disk quotas; local-path storage shares the node disk.")
	}
	for _, n := range r.Nodes {
		fmt.Fprintf(out, "\n%s: heartbeat %s; CPU sample %s; memory sample %s; disk sample %s\n", displayNetworkName(n.Name), resourceTime(n.LastHeartbeatAt), resourceTime(n.Usage.CPUObservedAt), resourceTime(n.Usage.MemoryObservedAt), resourceTime(n.Filesystem.ObservedAt))
		for _, warning := range n.Warnings {
			fmt.Fprintf(out, "  Warning: %s\n", displayNetworkName(warning))
		}
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(out, "Warning: %s\n", displayNetworkName(warning))
	}
}
