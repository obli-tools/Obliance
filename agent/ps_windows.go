//go:build windows
// +build windows

package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// runPS executes a PowerShell script with UTF-8 output encoding forced.
// This prevents garbled accented characters (e.g. "réseau" → "r�seau")
// on non-English Windows where the default console encoding is CP850/CP1252.
func runPS(script string) ([]byte, error) {
	return newCmd("powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", psUTF8Prefix+script,
	).Output()
}

// runPSContext is like runPS but with a context for timeouts.
func runPSContext(ctx context.Context, script string) ([]byte, error) {
	return newCmdContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", psUTF8Prefix+script,
	).Output()
}

// ── PowerShell version (probed once, cached) ──────────────────────────────────
//
// Windows 7 / Server 2008 R2 ship PowerShell 2.0, Server 2012 3.0, 8.1 /
// 2012 R2 4.0, everything newer 5.1. Features that need PowerShell 3+
// (ConvertTo-Json, Get-CimInstance, the Windows 8 cmdlet modules) branch on
// psAtLeast(); the version is also reported in the push body (psVersion).

var (
	psVerMu       sync.Mutex
	psVerString   string
	psVerMajor    int
	psVerProbed   bool
	psVerFailedAt time.Time
	// psVersionRunner is swapped by tests.
	psVersionRunner = runPSContext
)

// psVersionRetry: a failed probe (PowerShell missing / broken / timing out at
// boot) is retried at most this often instead of on every caller.
const psVersionRetry = 10 * time.Minute

func probePSVersionLocked() {
	if psVerProbed {
		return
	}
	if !psVerFailedAt.IsZero() && time.Since(psVerFailedAt) < psVersionRetry {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := psVersionRunner(ctx, psVersionScript)
	ver, major := parsePSVersion(string(out))
	if err != nil || major == 0 {
		psVerFailedAt = time.Now()
		log.Printf("PowerShell version probe failed (err=%v, output=%q) — retry in %s", err, truncateStr(string(out), 80), psVersionRetry)
		return
	}
	psVerString, psVerMajor, psVerProbed = ver, major, true
	log.Printf("PowerShell version: %s", ver)
}

// powerShellVersion returns the cached PowerShell version ("" while unknown).
func powerShellVersion() string {
	psVerMu.Lock()
	defer psVerMu.Unlock()
	probePSVersionLocked()
	return psVerString
}

var psVerAsyncBusy sync.Mutex

// powerShellVersionNoWait returns the cached version without blocking: while
// it is unknown, one background probe is started and "" returned (the push
// loop must never wait on a cold PowerShell start).
func powerShellVersionNoWait() string {
	psVerMu.Lock()
	ver, probed := psVerString, psVerProbed
	psVerMu.Unlock()
	if probed {
		return ver
	}
	if psVerAsyncBusy.TryLock() {
		go func() {
			defer psVerAsyncBusy.Unlock()
			powerShellVersion()
		}()
	}
	return ""
}

// psMajorVersion returns the PowerShell major version (0 = unknown).
func psMajorVersion() int {
	psVerMu.Lock()
	defer psVerMu.Unlock()
	probePSVersionLocked()
	return psVerMajor
}

// psAtLeast reports whether PowerShell >= major is known to be available. An
// unknown version answers false: callers then take the PowerShell 2.0-safe
// path, which works on every version.
func psAtLeast(major int) bool { return psMajorVersion() >= major }

// resetPSVersionCache is for tests.
func resetPSVersionCache() {
	psVerMu.Lock()
	psVerString, psVerMajor, psVerProbed, psVerFailedAt = "", 0, false, time.Time{}
	psVerMu.Unlock()
}
