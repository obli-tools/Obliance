//go:build !windows

package main

// windowsFirewallStatus is Windows-only (firewall_windows.go).
func windowsFirewallStatus() string { return "unknown" }
