package desktop

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDetectHostResourcesDarwin(t *testing.T) {
	var commands [][]string
	desktopMockRunner(t, func(ctx context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second {
			t.Fatal("host probe has no bounded deadline")
		}
		commands = append(commands, append([]string{name}, args...))
		switch strings.Join(append([]string{name}, args...), " ") {
		case "sysctl -n hw.logicalcpu":
			io.WriteString(out, "11\n")
		case "sysctl -n hw.memsize":
			io.WriteString(out, "38654705664\n")
		case "df -Pk /Users/test user":
			io.WriteString(out, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3 1000000 700000 300000 70% /System/Volumes/Data\n")
		default:
			t.Fatalf("unexpected host probe: %s %v", name, args)
		}
		return nil
	})
	host := detectHostResourcesFor(context.Background(), "darwin", "/Users/test user", 4)
	if host.CPUs != 11 || host.MemoryBytes == nil || *host.MemoryBytes != 36<<30 || host.StorageAvailableBytes == nil || *host.StorageAvailableBytes != 300000*1024 || host.StoragePath != "/Users/test user" || len(host.Warnings) != 0 {
		t.Fatalf("incorrect host resources: %+v", host)
	}
	if len(commands) != 3 || !reflect.DeepEqual(commands[2], []string{"df", "-Pk", "/Users/test user"}) {
		t.Fatalf("filesystem path was not passed as a literal argument: %v", commands)
	}
}

func TestDetectHostResourcesLinux(t *testing.T) {
	desktopMockRunner(t, func(_ context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
		switch {
		case name == "cat" && reflect.DeepEqual(args, []string{"/proc/meminfo"}):
			io.WriteString(out, "MemFree: 123 kB\nMemTotal: 8388608 kB\nMemAvailable: 6000000 kB\n")
		case name == "df" && reflect.DeepEqual(args, []string{"-Pk", "/home/test"}):
			io.WriteString(out, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/my disk 100000 100000 0 100% /home/test\n")
		default:
			t.Fatalf("unexpected host probe: %s %v", name, args)
		}
		return nil
	})
	host := detectHostResourcesFor(context.Background(), "linux", "/home/test", 8)
	if host.CPUs != 8 || host.MemoryBytes == nil || *host.MemoryBytes != 8<<30 || host.StorageAvailableBytes == nil || *host.StorageAvailableBytes != 0 || len(host.Warnings) != 0 {
		t.Fatalf("incorrect Linux host resources: %+v", host)
	}
}

func TestDetectHostResourcesWindows(t *testing.T) {
	path := `C:\Users\Test's $(user)`
	desktopMockRunner(t, func(_ context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
		if name != "powershell.exe" || len(args) != 4 || !reflect.DeepEqual(args[:3], []string{"-NoProfile", "-NonInteractive", "-Command"}) {
			t.Fatalf("unexpected PowerShell invocation: %s %v", name, args)
		}
		switch args[3] {
		case "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory":
			io.WriteString(out, "17179869184\r\n")
		case "([System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot('C:\\Users\\Test''s $(user)'))).AvailableFreeSpace":
			io.WriteString(out, "10737418240\r\n")
		default:
			t.Fatalf("unexpected PowerShell expression: %q", args[3])
		}
		return nil
	})
	host := detectHostResourcesFor(context.Background(), "windows", path, 8)
	if host.CPUs != 8 || host.MemoryBytes == nil || *host.MemoryBytes != 16<<30 || host.StorageAvailableBytes == nil || *host.StorageAvailableBytes != 10<<30 || host.StoragePath != path || len(host.Warnings) != 0 {
		t.Fatalf("incorrect Windows host resources: %+v", host)
	}
}

func TestDetectHostResourcesPartialAndUnavailable(t *testing.T) {
	desktopMockRunner(t, func(_ context.Context, name string, args []string, _ io.Reader, out, _ io.Writer) error {
		if name == "sysctl" && args[1] == "hw.memsize" {
			io.WriteString(out, "8589934592\n")
			return nil
		}
		return errors.New("probe unavailable")
	})
	host := detectHostResourcesFor(context.Background(), "darwin", "/", 6)
	if host.CPUs != 6 || host.MemoryBytes == nil || *host.MemoryBytes != 8<<30 || host.StorageAvailableBytes != nil || len(host.Warnings) != 2 {
		t.Fatalf("partial results not preserved: %+v", host)
	}
}

func TestDetectHostResourcesCancellationSkipsProcesses(t *testing.T) {
	desktopMockRunner(t, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("cancelled probe invoked a process")
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	host := detectHostResourcesFor(ctx, "linux", "/", 4)
	if host.CPUs != 4 || host.MemoryBytes != nil || host.StorageAvailableBytes != nil || len(host.Warnings) != 2 {
		t.Fatalf("cancelled probe did not return partial information: %+v", host)
	}
}

func TestDetectHostResourcesUnsupportedPlatform(t *testing.T) {
	desktopMockRunner(t, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("unsupported platform invoked a process")
		return nil
	})
	host := detectHostResourcesFor(context.Background(), "unknown", "/", 0)
	if host.CPUs != 1 || host.MemoryBytes != nil || host.StorageAvailableBytes != nil || len(host.Warnings) != 1 {
		t.Fatalf("unsupported host did not return partial information: %+v", host)
	}
}

func TestHostResourceParsersRejectMalformedAndOverflow(t *testing.T) {
	for _, data := range []string{"", "MemTotal: -1 kB", "MemTotal: 1024 MB", "MemTotal: 18446744073709551615 kB"} {
		if _, err := parseHostMeminfo(data); err == nil {
			t.Fatalf("accepted invalid meminfo: %q", data)
		}
	}
	for _, data := range []string{"", "header only", "header\n/dev/disk 100 50 -1 50% /", "header\n/dev/disk 100 50 18446744073709551615 50% /", "header\n/dev/disk invalid"} {
		if _, err := parseHostDF(data); err == nil {
			t.Fatalf("accepted invalid df output: %q", data)
		}
	}
}
