//go:build !windows
// +build !windows

package main

import "errors"

var errNotWindows = errors.New("windows inventory: not on Windows")

func collectWindowsInventorySnapshot() (winInvSnapshot, error) {
	return winInvSnapshot{}, errNotWindows
}

func collectUninstallRecords() ([]uninstallRecord, error) { return nil, errNotWindows }
