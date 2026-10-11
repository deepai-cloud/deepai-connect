//go:build linux && (amd64 || arm64)

// deepai-connect manages the public VPS services. Ship it only to connectivity service operators.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/deepai-cloud/deepai-connect/internal/connect"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := connect.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "deepai-connect:", err)
		os.Exit(1)
	}
}
