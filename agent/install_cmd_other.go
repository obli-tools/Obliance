//go:build !windows

package main

import (
	"context"
	"fmt"
	"os/exec"
)

// runInstallCmd on non-Windows simply runs the command with context timeout.
func runInstallCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// runInstallCmdLine: Windows only (msiexec).
func runInstallCmdLine(ctx context.Context, exe, cmdLine string) ([]byte, error) {
	return nil, fmt.Errorf("%s: not supported on this platform", exe)
}
