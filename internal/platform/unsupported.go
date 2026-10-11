//go:build !linux

package platform

import (
	"context"
	"errors"
)

// Non-Linux support is limited to development and credential tests. No desktop
// host installation implementation is included here.
func dockerPaths() []string               { return nil }
func hostEligible() error                 { return errors.New("DeepAI Connect requires a 64-bit Linux VPS") }
func startDocker(context.Context) error   { return hostEligible() }
func installDocker(context.Context) error { return hostEligible() }
