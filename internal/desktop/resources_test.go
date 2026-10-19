package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResourceQuantities(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  float64
	}{
		{"0", 0}, {"2", 2}, {"80m", 0.08}, {"50123u", 0.050123}, {"87342123n", 0.087342123},
		{"7034376Ki", 7034376 * 1024}, {"2.89Gi", 2.89 * (1 << 30)}, {"8G", 8e9}, {"+2.5Mi", 2.5 * (1 << 20)},
		{"1e3", 1000}, {"2E-3", 0.002}, {"1E", 1e18}, {".5", 0.5}, {"1000m", 1},
	} {
		got, err := parseResourceQuantity(tc.input)
		if err != nil || math.Abs(got-tc.want) > math.Max(1, tc.want)*1e-12 {
			t.Errorf("%s = %v (%v), want %v", tc.input, got, err, tc.want)
		}
	}
	for _, s := range []string{"", "-1", "NaN", "Inf", "3GiB", "2KK", "1e999", "1 2", "2K", "3foo"} {
		if _, err := parseResourceQuantity(s); err == nil {
			t.Errorf("accepted malformed quantity %q", s)
		}
	}
}

func resourcesNodeFixture(name, ready string, at time.Time) string {
	return fmt.Sprintf(`{"metadata":{"name":%q},"status":{"nodeInfo":{"architecture":"arm64"},"capacity":{"cpu":"2","memory":"3030Mi","ephemeral-storage":"7034376Ki"},"allocatable":{"cpu":"1500m","memory":"2500Mi","ephemeral-storage":"6000000Ki"},"conditions":[{"type":"Ready","status":%q,"lastHeartbeatTime":%q}]}}`, name, ready, at.Format(time.RFC3339))
}

func resourcesSummaryFixture(name string, at time.Time) string {
	return fmt.Sprintf(`{"node":{"nodeName":%q,"cpu":{"time":%q,"usageNanoCores":80000000},"memory":{"time":%q,"workingSetBytes":1073741824},"fs":{"time":%q,"capacityBytes":8589934592,"usedBytes":2147483648,"availableBytes":5905580032},"runtime":{"imageFs":{"time":%q,"capacityBytes":8589934592,"usedBytes":536870912,"availableBytes":5905580032}}}}`, name, at.Format(time.RFC3339), at.Format(time.RFC3339), at.Format(time.RFC3339), at.Format(time.RFC3339))
}

func TestCompactResourcesKeepsUnknownAndStaleUsageDistinctFromZero(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-6 * time.Minute)
	value := func(n float64) *float64 { return &n }
	n := resourceNode{
		Name: "worker", Ready: "True",
		Capacity:    resourceAmounts{CPUCores: value(2), MemoryBytes: value(4 << 30), EphemeralStorageBytes: value(6 << 30)},
		Allocatable: resourceAmounts{CPUCores: value(1), MemoryBytes: value(3 << 30)},
		Usage:       resourceUsage{CPUCores: value(0), MemoryWorkingSetBytes: value(1 << 30), CPUObservedAt: &now, MemoryObservedAt: &now},
		Filesystem:  resourceFilesystem{CapacityBytes: value(8 << 30), UsedBytes: value(2 << 30), ObservedAt: &now},
	}
	stale := n
	stale.Name, stale.Usage.CPUObservedAt = "stale", &old
	missing := resourceNode{Name: "offline", Ready: "False", Capacity: n.Capacity}
	r := resourcesReport{ObservedAt: now, Nodes: []resourceNode{n, stale, missing}}
	var out bytes.Buffer
	printResources(&out, &r)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected only a header and one row per node: %s", out.String())
	}
	for i, want := range []string{
		"NAME STATUS CPU CPU% MEMORY MEM% DISK DISK%",
		"worker Ready 2 0% 4Gi 25% 8Gi 25%",
		"stale Ready 2 <unknown> 4Gi 25% 8Gi 25%",
		"offline NotReady 2 <unknown> 4Gi <unknown> <unknown> <unknown>",
	} {
		if got := strings.Join(strings.Fields(lines[i]), " "); got != want {
			t.Errorf("row %d: %q, want %q", i, got, want)
		}
	}
	if got := resourcePercent(value(1), value(0), &now, now); got != "<unknown>" {
		t.Fatalf("zero capacity became a percentage: %s", got)
	}
	if got := resourcePercent(value(1), value(2), nil, now); got != "<unknown>" {
		t.Fatalf("undated usage was shown as current: %s", got)
	}
}

func TestResourcesPartialFailurePreservesCapacityAndMeasuredZero(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	desktopMockRunner(t, func(ctx context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 18*time.Second {
			t.Error("resource probe has no wall-clock limit")
		}
		command := args[len(args)-1]
		if !strings.Contains(command, "'--request-timeout=15s'") {
			t.Error("missing Kubernetes request timeout")
		}
		var data string
		switch {
		case strings.Contains(command, "'get' 'nodes'"):
			data = `{"items":[` + resourcesNodeFixture("hub", "True", now) + `,` + resourcesNodeFixture("worker", "Unknown", now.Add(-time.Hour)) + `]}`
		case strings.Contains(command, "metrics.k8s.io"):
			return errors.New("metrics service unavailable")
		case strings.Contains(command, "/nodes/hub/"):
			data = strings.ReplaceAll(resourcesSummaryFixture("hub", now), `"usageNanoCores":80000000`, `"usageNanoCores":0`)
		case strings.Contains(command, "/nodes/worker/"):
			return errors.New("kubelet unreachable")
		case strings.Contains(command, "'pv,pvc'"):
			data = `{"items":[]}`
		default:
			t.Errorf("unexpected read: %s", command)
			return errors.New("unexpected command")
		}
		_, err := io.WriteString(out, data)
		return err
	})
	var out bytes.Buffer
	if err := resourcesCommand(context.Background(), []string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var report resourcesReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("not JSON: %s (%v)", out.String(), err)
	}
	if report.SchemaVersion != 1 || len(report.Nodes) != 2 || len(report.Warnings) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	hub, worker := report.Nodes[0], report.Nodes[1]
	if hub.Usage.CPUCores == nil || *hub.Usage.CPUCores != 0 || hub.Filesystem.AvailableBytes == nil || *hub.Filesystem.AvailableBytes != 5905580032 {
		t.Fatalf("measured zero or actual available bytes lost: %+v", hub)
	}
	if *hub.Capacity.EphemeralStorageBytes == *hub.Filesystem.CapacityBytes {
		t.Fatal("API ephemeral capacity was conflated with live filesystem size")
	}
	if !worker.CapacityMayBeStale || *worker.Capacity.CPUCores != 2 || worker.Usage.CPUCores != nil || worker.Filesystem.CapacityBytes != nil || len(worker.Warnings) < 2 {
		t.Fatalf("missing probe invented usage: %+v", worker)
	}
	if !strings.Contains(out.String(), `"cpuCores":null`) || !report.Storage.Available {
		t.Fatalf("missing measurements or empty storage list changed: %s", out.String())
	}
	out.Reset()
	printResourceDetails(&out, &report)
	for _, want := range []string{"CPU CAP", "CPU ALLOC", "EPHEMERAL CAP", "Runtime image filesystem (GiB)", "not current free", "No persistent volumes or claims.", "may be stale", "?"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("human output missing %q: %s", want, out.String())
		}
	}
	_, images, _ := strings.Cut(out.String(), "Runtime image filesystem (GiB)\n")
	imageRows := strings.Split(images, "\n")
	if len(imageRows) < 2 || strings.Join(strings.Fields(imageRows[1]), " ") != "hub 8.00 0.50 5.50" {
		t.Fatalf("image usage was conflated with root usage: %s", images)
	}
	for _, args := range [][]string{nil, {"--details"}, {"-o", "json"}, {"--output=json"}} {
		out.Reset()
		if err := resourcesCommand(context.Background(), args, &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		switch {
		case len(args) == 0:
			if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 3 || !strings.HasPrefix(lines[0], "NAME ") {
				t.Fatalf("default command did not produce a compact node table: %s", out.String())
			}
		case args[0] == "--details":
			if !strings.Contains(out.String(), "Persistent storage (cluster-wide)") || !strings.Contains(out.String(), "may be stale") {
				t.Fatalf("details lost storage or diagnostics: %s", out.String())
			}
		default:
			if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"schemaVersion":1`) {
				t.Fatalf("JSON alias changed the structured report: %s", out.String())
			}
		}
	}
}

func TestResourcesMetricsFallbackAndNodeFilter(t *testing.T) {
	cfg := desktopTestConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	var summaries atomic.Int32
	desktopMockRunner(t, func(_ context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
		command := args[len(args)-1]
		var data string
		switch {
		case strings.Contains(command, "'get' 'nodes'"):
			data = `{"items":[` + resourcesNodeFixture("hub", "True", now) + `,` + resourcesNodeFixture("worker", "True", now) + `]}`
		case strings.Contains(command, "metrics.k8s.io"):
			data = fmt.Sprintf(`{"items":[{"metadata":{"name":"worker"},"timestamp":%q,"usage":{"cpu":"100m","memory":"512Mi"}}]}`, now.Format(time.RFC3339))
		case strings.Contains(command, "/proxy/stats/summary"):
			summaries.Add(1)
			if !strings.Contains(command, "/nodes/worker/") {
				t.Error("node filter still probed hub")
			}
			return errors.New("kubelet unavailable")
		case strings.Contains(command, "'pv,pvc'"):
			return errors.New("forbidden")
		default:
			t.Errorf("unexpected read: %s", command)
			return errors.New("unexpected command")
		}
		_, err := io.WriteString(out, data)
		return err
	})
	r, err := collectResources(context.Background(), cfg, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 1 || summaries.Load() != 1 {
		t.Fatalf("filter lost: %+v", r)
	}
	n := r.Nodes[0]
	if n.Usage.CPUCores == nil || *n.Usage.CPUCores != 0.1 || *n.Usage.MemoryWorkingSetBytes != 512*(1<<20) || n.Usage.CPUSource != "metrics.k8s.io" || !n.Usage.CPUObservedAt.Equal(now) {
		t.Fatalf("fallback failed: %+v", n)
	}
	if n.Filesystem.CapacityBytes != nil || r.Storage.Available || len(r.Warnings) != 1 {
		t.Fatalf("failed disk/storage reads became known: %+v", r)
	}
	if _, err := collectResources(context.Background(), cfg, "absent"); err == nil {
		t.Fatal("missing node did not fail")
	}
}

func TestResourceSummaryRequiresMatchingNodeAndDoesNotInventMissingFields(t *testing.T) {
	n := resourceNode{Name: "worker"}
	if err := applyResourceSummary([]byte(`{"node":{"nodeName":"other","cpu":{"usageNanoCores":8}}}`), &n); err == nil || n.Usage.CPUCores != nil {
		t.Fatal("wrong node accepted")
	}
	if err := applyResourceSummary([]byte(`{"node":{"nodeName":"worker","cpu":{"usageCoreNanoSeconds":9999999},"memory":{"usageBytes":200}}}`), &n); err != nil {
		t.Fatal(err)
	}
	if n.Usage.CPUCores != nil || n.Usage.MemoryWorkingSetBytes != nil || n.Filesystem.UsedBytes != nil {
		t.Fatalf("cumulative CPU or different memory measurement substituted: %+v", n)
	}
}

func TestPersistentResourcesKeepClaimsAndVolumesSeparate(t *testing.T) {
	data := []byte(`{"items":[{"kind":"PersistentVolume","metadata":{"name":"disk-a"},"spec":{"storageClassName":"local-path","capacity":{"storage":"10Gi"}},"status":{"phase":"Bound"}},{"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"app"},"spec":{"storageClassName":"local-path","volumeName":"disk-a","resources":{"requests":{"storage":"8Gi"}}},"status":{"phase":"Bound","capacity":{"storage":"10Gi"}}}]}`)
	storage := persistentResources{Scope: "cluster"}
	if err := parsePersistentResources(data, &storage); err != nil {
		t.Fatal(err)
	}
	if !storage.Available || len(storage.Volumes) != 1 || len(storage.Claims) != 1 || storage.Claims[0].VolumeName != "disk-a" || *storage.Claims[0].RequestedBytes != 8*(1<<30) || *storage.Volumes[0].CapacityBytes != 10*(1<<30) {
		t.Fatalf("storage metadata conflated: %+v", storage)
	}
	var out bytes.Buffer
	printResourceDetails(&out, &resourcesReport{Storage: storage})
	if !strings.Contains(out.String(), "not usage or guaranteed disk quotas") {
		t.Fatalf("PVC capacities represented as quota: %s", out.String())
	}
}

func TestResourcesInvalidArgumentsAndAPIFailureRemainJSON(t *testing.T) {
	cfg := desktopTestConfig(t)
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	desktopMockRunner(t, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		return errors.New("SSH unavailable")
	})
	for _, args := range [][]string{{"--json"}, {"-o", "json"}, {"--output=json"}, {"--bad", "--json"}, {"--bad", "-o", "json"}, {"--bad", "-o=json"}, {"--bad", "--output=json"}, {"--json", "unexpected"}, {"--json", "--node"}, {"--details", "-o", "json"}} {
		var out bytes.Buffer
		err := resourcesCommand(context.Background(), args, &out)
		if err == nil || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"error"`) {
			t.Errorf("%v: missing JSON error: %s (%v)", args, out.String(), err)
		}
	}
}

func TestResourcesBoundConcurrentProbes(t *testing.T) {
	cfg := desktopTestConfig(t)
	var active, maxActive atomic.Int32
	now := time.Now().UTC()
	desktopMockRunner(t, func(ctx context.Context, _ string, args []string, _ io.Reader, out, _ io.Writer) error {
		command := args[len(args)-1]
		if strings.Contains(command, "'get' 'nodes'") {
			nodes := []string{}
			for i := 0; i < 12; i++ {
				nodes = append(nodes, resourcesNodeFixture(fmt.Sprintf("worker-%d", i), "True", now))
			}
			_, err := io.WriteString(out, `{"items":[`+strings.Join(nodes, ",")+`]}`)
			return err
		}
		count := active.Add(1)
		defer active.Add(-1)
		for prev := maxActive.Load(); count > prev; prev = maxActive.Load() {
			if maxActive.CompareAndSwap(prev, count) {
				break
			}
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-ctx.Done():
		}
		return errors.New("endpoint unavailable")
	})
	if _, err := collectResources(context.Background(), cfg, ""); err != nil {
		t.Fatal(err)
	}
	if maxActive.Load() > 4 || maxActive.Load() < 2 {
		t.Fatalf("unexpected probe concurrency: %d", maxActive.Load())
	}
}
