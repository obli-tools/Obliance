//go:build !windows

package main

import "fmt"

// Windows-only native service helpers (services_windows.go); never reached on
// other platforms, where command_handler.go uses systemctl / launchctl / rc.

var errNotWindowsServices = fmt.Errorf("windows service manager not available on this platform")

func listServicesNative() ([]ServiceInfo, error) { return nil, errNotWindowsServices }

func startServiceNative(string) (string, error) { return "", errNotWindowsServices }

func stopServiceNative(string) (string, []string, error) { return "", nil, errNotWindowsServices }

func restartServiceNative(string) (string, error) { return "", errNotWindowsServices }

func serviceStartTypeAndStatus(string) (string, string, bool, error) {
	return "", "", false, errNotWindowsServices
}

func setServiceStartTypeNative(string, string) (string, string, error) {
	return "", "", errNotWindowsServices
}
