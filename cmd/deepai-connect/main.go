//go:build (linux || darwin || windows) && (amd64 || arm64)

// deepai-connect manages the host overlay and its Kubernetes cluster.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/deepai-cloud/deepai-connect/internal/desktop"
	"github.com/deepai-cloud/deepai-connect/internal/unified"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], runtime.GOOS); err != nil {
		fmt.Fprintln(os.Stderr, "deepai-connect:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, goos string) error {
	if len(args) == 0 {
		desktop.PrintStart(os.Stdout)
		return nil
	}
	if args[0] == "help" && len(args) > 1 {
		if len(args) != 2 {
			return fmt.Errorf("usage: deepai-connect help COMMAND")
		}
		args = []string{args[1], "--help"}
	}
	if desktop.Handles(args[0]) {
		return desktop.Run(ctx, args)
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		return unified.Run(ctx, args)
	}
	if !unified.Handles(args[0]) {
		for _, command := range append(append([]string{}, desktop.Commands...), unified.Commands...) {
			if commandDistance(args[0], command) <= 1 {
				return fmt.Errorf("unknown command %q; did you mean %q? Run deepai-connect help %s", args[0], command, command)
			}
		}
		return fmt.Errorf("unknown command %q; run deepai-connect --help", args[0])
	}
	hostHelp, hostJSON := false, false
	if args[0] == "host" {
		for _, arg := range args[1:] {
			if arg == "--" {
				break
			}
			switch arg {
			case "--help", "-h":
				hostHelp = true
			case "--json", "--json=true":
				hostJSON = true
			case "--json=false":
				hostJSON = false
			}
		}
	}
	if goos != "linux" && args[0] != "version" && args[0] != "--version" && !unified.PortableCommand(args) && !hostHelp && (len(args) != 2 || (args[1] != "--help" && args[1] != "-h")) {
		err := fmt.Errorf("%s manages a Linux host; run it inside the Linux VM or hub. For laptop administration, use deepai-connect setup --hub USER@HOST", args[0])
		if hostJSON {
			action := ""
			if len(args) > 1 {
				action = args[1]
			}
			if action == "startup" && len(args) > 2 {
				action += "-" + args[2]
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"schemaVersion": 1, "action": action, "platform": goos,
				"scope": "machine-boot", "services": []any{},
				"error": map[string]string{"code": "host_required", "message": err.Error()},
			})
		}
		return err
	}
	return unified.Run(ctx, args)
}

func commandDistance(a, b string) int {
	row := make([]int, len(b)+1)
	for j := range row {
		row[j] = j
	}
	for i := range len(a) {
		previous := row[0]
		row[0] = i + 1
		for j := range len(b) {
			replace := previous
			if a[i] != b[j] {
				replace++
			}
			previous = row[j+1]
			row[j+1] = min(row[j]+1, row[j+1]+1, replace)
		}
	}
	return row[len(b)]
}
