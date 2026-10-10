//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// lockFile is kept open for the life of the process: the flock is released
// by the kernel when the process exits (crash included), so no stale PID
// file or PID reuse can block a restart.
var lockFile *os.File

// singleInstanceLockPath is per user: one tray per logged-in user, several
// users (fast user switching) each get their own.
func singleInstanceLockPath() string {
	if dir, err := os.UserCacheDir(); err == nil {
		if err := os.MkdirAll(filepath.Join(dir, "obliance"), 0700); err == nil {
			return filepath.Join(dir, "obliance", "tray.lock")
		}
	}
	return filepath.Join(os.TempDir(), "obliance-tray-"+strconv.Itoa(os.Getuid())+".lock")
}

// acquireSingleInstanceLock takes an exclusive, non-blocking flock.
func acquireSingleInstanceLock() bool {
	f, err := os.OpenFile(singleInstanceLockPath(), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		// Cannot lock: better run twice than never show the icon.
		return true
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return false // another instance of this user holds the lock
	}
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
	lockFile = f
	return true
}
