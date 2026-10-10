//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	ld "github.com/obliance/agent/internal/launchd"
)

const (
	launchdLabel   = ld.AgentLabel
	launchdTarget  = ld.AgentTarget // "system/com.obliance.agent"
	launchdPlist   = "/Library/LaunchDaemons/com.obliance.agent.plist"
	installBinPath = "/usr/local/bin/obliance-agent"
	logFile        = "/var/log/obliance-agent.log"

	trayLabel     = ld.TrayLabel
	trayPlistPath = "/Library/LaunchAgents/com.obliance.tray.plist"
	trayBinPath   = "/usr/local/bin/obliance-tray"
)

// Rules for the daemon (com.obliance.agent): never use the legacy
// subcommands (load / unload, with or without -w) nor the "disable" one.
// The legacy load exits 0 without loading a job that carries a persistent "disabled"
// override (disabled.plist), which made the installer report success while
// nothing ran. Only bootout / enable / bootstrap / kickstart / print on the
// system/com.obliance.agent target are used, and the real state is checked.

// runAsService checks for "install" / "uninstall" positional arguments
// (after flag.Parse, these appear in flag.Args()).
func runAsService(urlFlag, keyFlag *string) bool {
	args := flag.Args()
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "install":
		installLaunchdService(*urlFlag, *keyFlag)
		return true
	case "uninstall":
		uninstallLaunchdService()
		return true
	}
	return false
}

// launchctl runs launchctl and returns trimmed combined output and exit code
// (-1 if the command could not be run at all).
func launchctl(args ...string) (string, int, error) {
	out, err := newCmd("launchctl", args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err == nil {
		return s, 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return s, ee.ExitCode(), err
	}
	return s, -1, err
}

// launchdServiceLoaded reports whether launchd knows the daemon.
func launchdServiceLoaded() bool {
	_, _, err := launchctl("print", launchdTarget)
	return err == nil
}

// stopLaunchdService boots the daemon out of the system domain and waits
// until launchd no longer knows it. Never disables the job.
func stopLaunchdService() error {
	out, code, bootErr := launchctl("bootout", launchdTarget)
	// 3 (ESRCH) / 113 (service not found) = not loaded: already stopped.
	// Any other failure is only reported if the job is still loaded below.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if !launchdServiceLoaded() {
			return nil
		}
		if time.Now().After(deadline) {
			if bootErr != nil && code != 3 && code != 113 {
				return fmt.Errorf("launchctl bootout %s failed (exit %d): %s", launchdTarget, code, out)
			}
			return fmt.Errorf("%s still loaded 10s after bootout", launchdTarget)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// startLaunchdService (re)loads the daemon with the modern launchctl API and
// verifies it actually reaches "state = running" and stays up.
func startLaunchdService() error {
	if err := stopLaunchdService(); err != nil {
		return err
	}
	// Clear any persistent "disabled" override (disabled.plist), whoever set
	// it (admin `unload -w`, Login Items / Background Task Management, MDM).
	if out, code, err := launchctl("enable", launchdTarget); err != nil {
		return fmt.Errorf("launchctl enable %s failed (exit %d): %s", launchdTarget, code, out)
	}
	// bootstrap right after a bootout can fail transiently with
	// "5: Input/output error": retry a few times.
	var lastOut string
	var lastCode int
	var bootErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		lastOut, lastCode, bootErr = launchctl("bootstrap", "system", launchdPlist)
		if bootErr == nil || launchdServiceLoaded() {
			bootErr = nil
			break
		}
	}
	if bootErr != nil {
		return fmt.Errorf("launchctl bootstrap system %s failed (exit %d): %s", launchdPlist, lastCode, lastOut)
	}
	// No -k: RunAtLoad normally already started it; this is a no-op if running.
	if out, code, err := launchctl("kickstart", launchdTarget); err != nil {
		return fmt.Errorf("launchctl kickstart %s failed (exit %d): %s", launchdTarget, code, out)
	}
	return waitLaunchdRunning(15 * time.Second)
}

// waitLaunchdRunning waits until the daemon is reported running with the same
// PID on two observations 2 s apart (a binary that crashes at start-up is
// briefly "running" before KeepAlive relaunches it).
func waitLaunchdRunning(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var out string
	lastPID := 0
	var since time.Time
	for {
		var err error
		out, _, err = launchctl("print", launchdTarget)
		if err == nil && ld.IsRunning(out) {
			pid := ld.PID(out)
			if pid != lastPID {
				lastPID, since = pid, time.Now()
			} else if time.Since(since) >= 2*time.Second {
				return nil
			}
		} else {
			lastPID = 0
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not running after %s; launchctl print output:\n%s", launchdTarget, timeout, out)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// detachFromCallerProcessGroup moves the installer into its own session.
// When install/uninstall is started by the running daemon itself (run_script,
// scenario), it inherits the daemon's process group, and launchd kills that
// group on bootout: the installer would die halfway, leaving no daemon at
// all. Setsid fails harmlessly when we already lead our own group (in which
// case we are not in the daemon's group either). Output keeps going to the
// inherited stdout/stderr.
func detachFromCallerProcessGroup() {
	_, _ = syscall.Setsid()
}

// installLaunchdService:
//  1. Initialises the agent config (saves to /etc/obliance-agent/config.json)
//  2. Stops the daemon, then installs the current binary to
//     /usr/local/bin/obliance-agent (temp file + rename, never in place)
//  3. Writes the launchd plist
//  4. Starts the daemon (bootout / enable / bootstrap / kickstart) and
//     verifies it runs; exits 1 otherwise
//  5. Installs the menu-bar tray LaunchAgent (non fatal)
func installLaunchdService(urlArg, keyArg string) {
	if urlArg == "" || keyArg == "" {
		fmt.Fprintln(os.Stderr, "Usage: sudo obliance-agent --url <URL> --key <KEY> install")
		os.Exit(1)
	}
	detachFromCallerProcessGroup()

	// ── 1. Save config ──────────────────────────────────────────────────────
	cfg := setupConfig(urlArg, keyArg)
	fmt.Printf("Config saved to %s\n", configFile)

	// ── 2. Stop the daemon, install the binary ──────────────────────────────
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine binary path: %v\n", err)
		os.Exit(1)
	}
	// Resolve symlinks so we copy the real binary
	exePath, _ = filepath.EvalSymlinks(exePath)

	// Stop first so a running instance never sees its executable replaced.
	if err := stopLaunchdService(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	if exePath != installBinPath {
		// copyFile writes a temp file then renames it: rewriting a signed
		// Mach-O in place can get later executions SIGKILLed on arm64
		// (code signature cache mismatch).
		if err := copyFile(exePath, installBinPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to copy binary to %s: %v\n", installBinPath, err)
			fmt.Fprintln(os.Stderr, "Run with sudo or ensure /usr/local/bin is writable.")
			os.Exit(1)
		}
		fmt.Printf("Binary installed to %s\n", installBinPath)
	}

	// ── 3. Write plist ──────────────────────────────────────────────────────
	plistContent := ld.DaemonPlist(launchdLabel, installBinPath, logFile)
	if err := writeFileAtomic(launchdPlist, []byte(plistContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write plist to %s: %v\n", launchdPlist, err)
		os.Exit(1)
	}
	fmt.Printf("Plist written to %s\n", launchdPlist)

	// ── 4. Start daemon and verify ──────────────────────────────────────────
	if err := startLaunchdService(); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Obliance Agent failed to start: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Obliance Agent installed and running (label: %s)\n", launchdLabel)
	fmt.Printf("  Logs: %s\n", logFile)
	fmt.Println("  To stop:      sudo launchctl bootout " + launchdTarget)
	fmt.Println("  To uninstall: sudo obliance-agent uninstall")

	// ── 5. Install tray (menu bar icon) ─────────────────────────────────────
	// The tray binary is downloaded from the same server endpoint the agent
	// itself uses. Failure is non-fatal — the agent works without the tray.
	if err := installTray(cfg.ServerURL); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: tray installation skipped: %v\n", err)
	}
}

// guiSessionUIDs returns the UIDs that currently own an Aqua (GUI) session.
func guiSessionUIDs() []int {
	out, err := newCmd("ps", "-axo", "uid=,comm=").Output()
	if err != nil {
		return nil
	}
	return ld.GUISessionUIDs(string(out))
}

// installTray downloads the obliance-tray binary for the current architecture
// and registers it as a per-user LaunchAgent. launchd starts it in the Aqua
// session of every user that logs in; it is also bootstrapped right away in
// the GUI sessions already open.
func installTray(serverURL string) error {
	arch := runtime.GOARCH // "amd64" or "arm64"
	filename := fmt.Sprintf("obliance-tray-darwin-%s", arch)
	url := fmt.Sprintf("%s/api/agent/download/%s", strings.TrimRight(serverURL, "/"), filename)

	fmt.Printf("Downloading tray binary from %s…\n", url)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("tray binary not available on server (skipped)")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	// Temp file + rename: a running tray keeps its old inode.
	if err := writeReaderAtomic(trayBinPath, resp.Body, 0755); err != nil {
		return fmt.Errorf("write %s: %w", trayBinPath, err)
	}

	// Clear the quarantine attribute Gatekeeper adds to downloaded files so
	// the LaunchAgent can exec it without a security warning.
	_ = newCmd("xattr", "-d", "com.apple.quarantine", trayBinPath).Run()

	fmt.Printf("Tray binary installed to %s\n", trayBinPath)

	// ── Write LaunchAgent plist ─────────────────────────────────────────────
	if err := writeFileAtomic(trayPlistPath, []byte(ld.TrayAgentPlist(trayLabel, trayBinPath)), 0644); err != nil {
		return fmt.Errorf("write plist %s: %w", trayPlistPath, err)
	}
	fmt.Printf("LaunchAgent plist written to %s\n", trayPlistPath)

	// ── (Re)start it in every open GUI session ──────────────────────────────
	uids := guiSessionUIDs()
	if len(uids) == 0 {
		fmt.Println("Tray will appear in the menu bar at the next user login.")
		return nil
	}
	for _, uid := range uids {
		domain := "gui/" + strconv.Itoa(uid)
		target := domain + "/" + trayLabel
		_, _, _ = launchctl("bootout", target)
		_, _, _ = launchctl("enable", target)
		var out string
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Second)
			}
			if out, _, err = launchctl("bootstrap", domain, trayPlistPath); err == nil {
				break
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: tray bootstrap in %s failed (it will start at next login): %s\n", domain, out)
		} else {
			fmt.Printf("Tray loaded for user UID %d\n", uid)
		}
	}
	return nil
}

// uninstallLaunchdService stops and removes the launchd daemon AND the
// per-user tray LaunchAgent.
func uninstallLaunchdService() {
	detachFromCallerProcessGroup()

	fmt.Println("Stopping launchd daemon…")
	if err := stopLaunchdService(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	// Best-effort tray removal in every open GUI session, then delete the
	// plist + binary (future logins no longer start it).
	for _, uid := range guiSessionUIDs() {
		_, _, _ = launchctl("bootout", fmt.Sprintf("gui/%d/%s", uid, trayLabel))
	}

	for _, path := range []string{launchdPlist, installBinPath, trayPlistPath, trayBinPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", path, err)
		} else if err == nil {
			fmt.Printf("Removed %s\n", path)
		}
	}

	fmt.Println("\n✓ Obliance Agent uninstalled.")
	fmt.Println("  Config and logs were kept. Remove manually if needed:")
	fmt.Printf("    sudo rm -rf %s %s\n", configDir, logFile)
}

// copyFile copies src to dst with the given permission bits, through a temp
// file renamed over dst (never rewrites dst in place).
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeReaderAtomic(dst, in, mode)
}

// writeFileAtomic writes data to path through a temp file + rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeReaderAtomic(path, strings.NewReader(string(data)), mode)
}

// writeReaderAtomic streams r into path+".new", fsyncs it, sets mode and
// renames it over path.
func writeReaderAtomic(path string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".new"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
