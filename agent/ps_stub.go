//go:build !windows
// +build !windows

package main

import (
	"context"
	"fmt"
)

func runPS(_ string) ([]byte, error) {
	return nil, fmt.Errorf("powershell not available on this platform")
}

func runPSContext(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("powershell not available on this platform")
}

// powerShellVersion: no Windows PowerShell outside Windows.
func powerShellVersion() string { return "" }

func psMajorVersion() int { return 0 }

func psAtLeast(_ int) bool { return false }

func powerShellVersionNoWait() string { return "" }
