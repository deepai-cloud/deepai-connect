package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMultipassSizeUnitsAndExactRounding(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  uint64
	}{
		{"8G", 8 << 30}, {"8GB", 8 << 30}, {"8gib", 8 << 30},
		{"512M", 512 << 20}, {"1.5GiB", 3 << 29}, {"1.2KiB", 1228},
		{"8589934591B", (8 << 30) - 1}, {"8192", 8192},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseMultipassSize(tt.input)
			if err != nil || got != tt.want {
				t.Fatalf("parseMultipassSize(%q) = %d, %v; want %d", tt.input, got, err, tt.want)
			}
		})
	}
	for _, input := range []string{"", "0", "-2G", "NaN", "1.1B", "1.1", "1TiB", "8Gi", "1e9", "2 G", "9223372036854775808", "0.0001K"} {
		if _, err := parseMultipassSize(input); err == nil {
			t.Errorf("accepted invalid size %q", input)
		}
	}
}

func vmTestBackend(t *testing.T, state string, failSetting string) *[]string {
	t.Helper()
	desktopTestConfig(t) // Explicit --name must work with no hub configuration.
	oldHost := readVMHostResources
	readVMHostResources = func(context.Context) HostResources {
		memory, disk := uint64(36<<30), uint64(7<<30)
		return HostResources{CPUs: 11, MemoryBytes: &memory, StorageAvailableBytes: &disk, StoragePath: "/Users/test"}
	}
	t.Cleanup(func() { readVMHostResources = oldHost })
	var calls []string
	desktopMockRunner(t, func(ctx context.Context, command string, args []string, _ io.Reader, out, _ io.Writer) error {
		if command != "multipass" {
			t.Fatalf("unexpected command %s", command)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 6*time.Minute {
			t.Fatalf("command lacks a bounded deadline: %v", args)
		}
		call := strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "list --format json":
			if state == "" {
				fmt.Fprint(out, `{"list":[]}`)
			} else {
				fmt.Fprintf(out, `{"list":[{"name":"worker-1","state":%q}]}`, state)
			}
		case "get local.worker-1.cpus":
			fmt.Fprintln(out, "2")
		case "get local.worker-1.memory":
			fmt.Fprintln(out, "3GiB")
		case "get local.worker-1.disk":
			fmt.Fprintln(out, "8GiB")
		case "get client.primary-name":
			fmt.Fprintln(out, "primary")
		default:
			if strings.HasPrefix(call, "set local.worker-1.") {
				if strings.Contains(call, "."+failSetting+"=") && failSetting != "" {
					return errors.New("backend rejected update")
				}
				return nil
			}
			if strings.HasPrefix(call, "launch 24.04 ") {
				return nil
			}
			t.Fatalf("unexpected operation: %s", call)
		}
		return nil
	})
	return &calls
}

func TestVMResourcesWithoutHubOrGuestSSH(t *testing.T) {
	calls := vmTestBackend(t, "Running", "")
	var out bytes.Buffer
	if err := runVMTo(context.Background(), []string{"resources", "--name", "worker-1", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var r vmResourceReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.State != "Running" || r.Grant.CPUs != 2 || r.Grant.MemoryBytes != 3<<30 || r.Grant.DiskBytes != 8<<30 || r.Host.CPUs != 11 || *r.Host.MemoryBytes != 36<<30 {
		t.Fatalf("unexpected resource report: %+v", r)
	}
	if len(*calls) != 4 {
		t.Fatalf("unexpected calls: %v", *calls)
	}
	if !strings.Contains(r.Notes, "not reserved host space") {
		t.Fatal("missing reservation distinction")
	}
}

func TestVMResourcesUsesSavedVM(t *testing.T) {
	vmTestBackend(t, "Stopped", "")
	cfg := Config{Hub: "root@hub.example", StateDir: defaultStateDir, OverlayIP: "100.96.0.1", VM: "worker-1"}
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runVMTo(context.Background(), []string{"resources"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"worker-1 (Stopped)", "2 vCPU", "3.00 GiB RAM", "8.00 GiB virtual disk", "36.00 GiB physical RAM", "7.00 GiB available on /Users/test"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func TestVMConfigurePreviewNeverMutates(t *testing.T) {
	calls := vmTestBackend(t, "Running", "")
	var out bytes.Buffer
	err := runVMTo(context.Background(), []string{"configure", "--name", "worker-1", "--cpus", "4", "--memory", "8G", "--disk", "20G"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 4 || !strings.Contains(out.String(), "Preview only") || !strings.Contains(out.String(), "exceeds currently available host space") {
		t.Fatalf("unsafe or incomplete preview: calls=%v output=%s", *calls, out.String())
	}
}

func TestVMConfigureRejectsInvalidPlanBeforeAnyCommands(t *testing.T) {
	for _, flags := range [][]string{
		{"--cpus", "4", "--memory", "8G"},
		{"--cpus", "0", "--memory", "8G", "--disk", "8G"},
		{"--cpus", "4", "--memory", "2G", "--disk", "0"},
		{"--cpus", "4", "--memory", "128M", "--disk", "8G"},
		{"--cpus", "4", "--memory", "8G", "--disk", "500M"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			calls := vmTestBackend(t, "Stopped", "")
			args := append([]string{"configure", "--name", "worker-1", "--apply"}, flags...)
			if err := runVMTo(context.Background(), args, io.Discard); err == nil {
				t.Fatal("invalid request succeeded")
			}
			if len(*calls) != 0 {
				t.Fatalf("ran commands before validating whole request: %v", *calls)
			}
		})
	}
}

func TestVMConfigureRejectsDiskShrinkBeforeChanges(t *testing.T) {
	calls := vmTestBackend(t, "Stopped", "")
	err := runVMTo(context.Background(), []string{"configure", "--name", "worker-1", "--cpus", "4", "--memory", "8G", "--disk", "8589934591B", "--apply"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot shrink") || len(*calls) != 4 {
		t.Fatalf("shrink rejection: calls=%v err=%v", *calls, err)
	}
}

func TestVMConfigureOnlyAppliesWhenStopped(t *testing.T) {
	for _, state := range []string{"Running", "Suspended", "Deleted", "Unknown"} {
		t.Run(state, func(t *testing.T) {
			calls := vmTestBackend(t, state, "")
			err := runVMTo(context.Background(), []string{"configure", "--name", "worker-1", "--cpus", "4", "--memory", "8G", "--disk", "8G", "--apply"}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "multipass stop worker-1") || len(*calls) != 4 {
				t.Fatalf("state=%s calls=%v err=%v", state, *calls, err)
			}
		})
	}
}

func TestVMConfigureStoppedPreservesIdentityAndGrowsDiskLast(t *testing.T) {
	calls := vmTestBackend(t, "Stopped", "")
	err := runVMTo(context.Background(), []string{"configure", "--name", "worker-1", "--cpus", "4", "--memory", "8G", "--disk", "20G", "--apply"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"set local.worker-1.cpus=4", "set local.worker-1.memory=8589934592", "set local.worker-1.disk=21474836480"}
	if !reflect.DeepEqual((*calls)[4:], want) {
		t.Fatalf("mutations = %v; want %v", (*calls)[4:], want)
	}
}

func TestVMConfigureReportsPartialFailureWithoutRollback(t *testing.T) {
	calls := vmTestBackend(t, "Stopped", "memory")
	err := runVMTo(context.Background(), []string{"configure", "--name", "worker-1", "--cpus", "4", "--memory", "8G", "--disk", "20G", "--apply"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "confirmed settings changed: cpus; memory failed") || !strings.Contains(err.Error(), "outcome may be uncertain") {
		t.Fatalf("failure lost partial state: %v", err)
	}
	if len(*calls) != 6 {
		t.Fatalf("unexpected changes after failure: %v", *calls)
	}
}

func TestVMConfigureNoopDoesNotSet(t *testing.T) {
	calls := vmTestBackend(t, "Stopped", "")
	err := runVMTo(context.Background(), []string{"configure", "--name", "worker-1", "--cpus", "2", "--memory", "3G", "--disk", "8G", "--apply"}, io.Discard)
	if err != nil || len(*calls) != 4 {
		t.Fatalf("no-op config: calls=%v err=%v", *calls, err)
	}
}

func TestVMCreatePreviewAndApply(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(fmt.Sprint(apply), func(t *testing.T) {
			calls := vmTestBackend(t, "", "")
			args := []string{"create", "--name", "worker-1", "--cpus", "4", "--memory", "8G", "--disk", "20G"}
			if apply {
				args = append(args, "--apply")
			}
			var out bytes.Buffer
			if err := runVMTo(context.Background(), args, &out); err != nil {
				t.Fatal(err)
			}
			if !apply {
				if len(*calls) != 2 || !strings.Contains(out.String(), "no VM created") {
					t.Fatalf("preview changed state: %v, %s", *calls, out.String())
				}
			} else {
				want := "launch 24.04 --name worker-1 --cpus 4 --memory 8589934592 --disk 21474836480 --timeout 300"
				if len(*calls) != 3 || (*calls)[2] != want {
					t.Fatalf("create did not apply explicit grant: %v", *calls)
				}
			}
		})
	}
}

func TestVMCreateRefusesExistingIdentityAndPrimaryHomeMount(t *testing.T) {
	for _, tt := range []struct{ state, name, want string }{
		{"Stopped", "worker-1", "already exists"},
		{"", "primary", "automatically mounts"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := vmTestBackend(t, tt.state, "")
			err := runVMTo(context.Background(), []string{"create", "--name", tt.name, "--cpus", "4", "--memory", "8G", "--disk", "20G", "--apply"}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("refusal: calls=%v err=%v", *calls, err)
			}
			for _, call := range *calls {
				if strings.HasPrefix(call, "launch ") {
					t.Fatalf("launched forbidden VM: %v", *calls)
				}
			}
		})
	}
}
