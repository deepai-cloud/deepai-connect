//go:build linux && (amd64 || arm64)

// deepai-connect manages the host overlay and its Kubernetes cluster.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/deepai-cloud/deepai-connect/internal/unified"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := unified.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "deepai-connect:", err)
		os.Exit(1)
	}
}
