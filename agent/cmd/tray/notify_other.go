//go:build !windows

package main

// showWindowsNotification is only reached on Windows (showToast switches on
// runtime.GOOS); this stub keeps the other platforms compiling.
func showWindowsNotification(_, _ string) {}
