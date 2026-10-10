//go:build darwin

package main

import (
	"log"
	"os"
	"syscall"
	"time"
)

// restartWithNewBinary asks launchd to kill and relaunch the daemon so the new
// binary at installBinPath is started by launchd itself. Falls back to an
// in-place exec when not running under launchd (e.g. manual run).
func restartWithNewBinary(exePath string) {
	log.Printf("Auto-update: restarting via launchctl kickstart -k %s", launchdTarget)
	out, code, err := launchctl("kickstart", "-k", launchdTarget)
	if err == nil {
		// launchd sends SIGTERM to this process; exit as a safety net.
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	log.Printf("Auto-update: kickstart failed (exit %d: %s) — re-executing %s in place", code, out, exePath)
	if err := syscall.Exec(exePath, os.Args, os.Environ()); err != nil {
		log.Printf("Auto-update: re-exec failed (%v) — exiting", err)
	}
	os.Exit(0)
}
