//go:build darwin

package main

import "os"

// privacyFileMode: on macOS privacy.json is never world-writable. The
// menu-bar tray (unprivileged) asks the daemon through the local socket
// (tray_ipc_darwin.go). The admin lock stays "no owner write bit" (0444).
const privacyFileMode os.FileMode = 0644

// hardenPrivacyFile removes the group/world write bits that agents before
// the local socket set on privacy.json (0666). A read-only (locked) file is
// left as is, as is anything that is not a regular file.
func hardenPrivacyFile() {
	info, err := os.Lstat(privacyFile)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if perm := info.Mode().Perm(); perm&0022 != 0 {
		_ = os.Chmod(privacyFile, perm&^0022)
	}
}
