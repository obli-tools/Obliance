//go:build !darwin

package main

// startTrayIPC is macOS only (tray_ipc_darwin.go): the Windows tray writes
// privacy.json under an NTFS ACL and the Linux tray writes it directly.
func startTrayIPC() {}
