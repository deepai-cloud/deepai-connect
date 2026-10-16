//go:build (linux || darwin) && (amd64 || arm64)

// deepai-connect manages the host overlay and its Kubernetes cluster.
package main

import (
	"context"
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
	if len(args) > 0 && desktop.Handles(args[0]) {
		return desktop.Run(ctx, args)
	}
	if goos != "linux" && len(args) > 0 {
		switch args[0] {
		case "help", "--help", "-h", "version", "--version":
		default:
			if len(args) != 2 || (args[1] != "--help" && args[1] != "-h") {
				return fmt.Errorf("%s manages a Linux host; run it inside the Linux VM or hub. For laptop administration, use deepai-connect setup --hub USER@HOST", args[0])
			}
		}
	}
	return unified.Run(ctx, args)
}
