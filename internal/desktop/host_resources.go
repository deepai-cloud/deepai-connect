package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HostResources describes the host, not an allocation or reservation. The
// measured filesystem can differ from the volume holding Multipass VM images.
type HostResources struct {
	CPUs                  int      `json:"cpus"`
	MemoryBytes           *uint64  `json:"memoryBytes"`
	StorageAvailableBytes *uint64  `json:"storageAvailableBytes"`
	StoragePath           string   `json:"storagePath"`
	Warnings              []string `json:"warnings,omitempty"`
}

func detectHostResources(ctx context.Context) HostResources {
	storagePath, err := os.UserHomeDir()
	if err != nil || storagePath == "" {
		storagePath = string(os.PathSeparator)
		if runtime.GOOS == "windows" {
			storagePath = os.Getenv("SystemDrive") + `\`
		}
	}
	host := detectHostResourcesFor(ctx, runtime.GOOS, storagePath, runtime.NumCPU())
	if err != nil {
		host.Warnings = append(host.Warnings, "Home directory unavailable; storage was measured on the system root filesystem.")
	}
	return host
}

// Parameters keep platform probes testable without probing the test host. One
// shared timeout bounds the complete inspection, including unavailable tools.
func detectHostResourcesFor(ctx context.Context, goos, storagePath string, cpuFallback int) HostResources {
	if cpuFallback < 1 {
		cpuFallback = 1
	}
	host := HostResources{CPUs: cpuFallback, StoragePath: storagePath}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	read := func(name string, args ...string) (string, error) {
		if err := bounded.Err(); err != nil {
			return "", err
		}
		var out bytes.Buffer
		if err := runProcess(bounded, name, args, nil, &out, io.Discard); err != nil {
			return "", err
		}
		return strings.TrimSpace(out.String()), nil
	}
	warn := func(resource string) {
		host.Warnings = append(host.Warnings, resource+" could not be detected; inspect the host before choosing a resource grant.")
	}
	var memory string
	var memoryErr error
	switch goos {
	case "darwin":
		cpu, err := read("sysctl", "-n", "hw.logicalcpu")
		if n, parseErr := strconv.Atoi(cpu); err == nil && parseErr == nil && n > 0 {
			host.CPUs = n
		} else {
			host.Warnings = append(host.Warnings, "Host logical CPU probe unavailable; using the CPU count visible to this process.")
		}
		memory, memoryErr = read("sysctl", "-n", "hw.memsize")
	case "linux":
		// /proc/meminfo contains kernel memory counters, not private user data.
		memory, memoryErr = read("cat", "/proc/meminfo")
	case "windows":
		memory, memoryErr = read("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
	default:
		host.Warnings = append(host.Warnings, fmt.Sprintf("Memory and storage auto-detection is unavailable on %s; using the CPU count visible to this process.", goos))
		return host
	}
	if memoryErr == nil {
		var n uint64
		if goos == "linux" {
			n, memoryErr = parseHostMeminfo(memory)
		} else {
			n, memoryErr = strconv.ParseUint(memory, 10, 64)
		}
		if memoryErr == nil && n > 0 {
			host.MemoryBytes = &n
		}
	}
	if host.MemoryBytes == nil {
		warn("Host physical memory")
	}
	var storage string
	var storageErr error
	if goos == "windows" {
		// A PowerShell single-quoted literal does not interpolate expressions.
		literalPath := "'" + strings.ReplaceAll(storagePath, "'", "''") + "'"
		command := "([System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot(" + literalPath + "))).AvailableFreeSpace"
		storage, storageErr = read("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	} else {
		storage, storageErr = read("df", "-Pk", storagePath)
	}
	if storageErr == nil {
		var n uint64
		if goos == "windows" {
			n, storageErr = strconv.ParseUint(storage, 10, 64)
		} else {
			n, storageErr = parseHostDF(storage)
		}
		if storageErr == nil {
			host.StorageAvailableBytes = &n
		}
	}
	if host.StorageAvailableBytes == nil {
		warn("Available storage on " + storagePath)
	}
	return host
}

func parseHostMeminfo(data string) (uint64, error) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			return hostKiBBytes(fields[1])
		}
	}
	return 0, errors.New("MemTotal in kB is missing")
}

func parseHostDF(data string) (uint64, error) {
	lines := strings.Split(strings.TrimSpace(data), "\n")
	if len(lines) < 2 {
		return 0, errors.New("filesystem data is missing")
	}
	// POSIX df -P keeps each filesystem on one line. Find the capacity column
	// so spaces in a filesystem name or mount path do not shift the byte count.
	fields := strings.Fields(lines[len(lines)-1])
	for i := 4; i < len(fields)-1; i++ {
		if strings.HasSuffix(fields[i], "%") {
			if _, err := strconv.ParseUint(strings.TrimSuffix(fields[i], "%"), 10, 64); err == nil {
				return hostKiBBytes(fields[i-1])
			}
		}
	}
	return 0, errors.New("available filesystem blocks are missing")
}

func hostKiBBytes(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > math.MaxUint64/1024 {
		return 0, errors.New("invalid KiB quantity")
	}
	return n * 1024, nil
}
