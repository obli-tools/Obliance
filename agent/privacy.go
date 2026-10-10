package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ── Privacy Mode ────────────────────────────────────────────────────────────────
//
// Privacy mode is controlled locally via the tray app or remotely via a server
// command. State is persisted in a JSON file so both the agent service (SYSTEM)
// and the tray app (user session) can read/write it atomically.

// privacyState is the on-disk format of privacy.json.
type privacyState struct {
	Enabled   bool   `json:"enabled"`
	ChangedAt string `json:"changedAt"`
	ChangedBy string `json:"changedBy"` // "user" or "remote"
}

var (
	privacyMu      sync.RWMutex
	privacyEnabled bool
	privacyFile    string
)

func init() {
	privacyFile = filepath.Join(configDir, "privacy.json")
}

// IsPrivacyMode returns the current in-memory privacy state.
func IsPrivacyMode() bool {
	privacyMu.RLock()
	defer privacyMu.RUnlock()
	return privacyEnabled
}

// IsPrivacyLocked returns true when privacy.json is read-only (admin lock).
func IsPrivacyLocked() bool {
	info, err := os.Stat(privacyFile)
	if err != nil {
		return false
	}
	// On Windows, os.FileMode only exposes the read-only attribute.
	// A read-only file has no write bit set.
	return info.Mode().Perm()&0200 == 0
}

// SetPrivacyMode updates privacy state, persists to disk, and manages the
// ObliReach service accordingly. Returns an error if the file is locked
// (read-only).
func SetPrivacyMode(enabled bool, changedBy string) error {
	if IsPrivacyLocked() {
		return fmt.Errorf("Privacy Mode locked on this device")
	}

	state := privacyState{
		Enabled:   enabled,
		ChangedAt: time.Now().UTC().Format(time.RFC3339),
		ChangedBy: changedBy,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("privacy: marshal: %w", err)
	}
	// privacyFileMode (privacy_mode_*.go): 0666 on Linux so the tray process
	// (running as the logged-in user) can also update the file when the user
	// clicks the tray menu; on Windows the mode is essentially ignored (ACLs
	// govern access). On macOS 0644: the tray goes through the root-owned
	// local socket instead (tray_ipc_darwin.go), the file is never
	// world-writable. Explicit Chmod after WriteFile because the daemon's
	// umask (typically 022) would otherwise strip the world-write bit.
	if err := os.WriteFile(privacyFile, data, privacyFileMode); err != nil {
		return fmt.Errorf("privacy: write: %w", err)
	}
	_ = os.Chmod(privacyFile, privacyFileMode)
	// On Windows, chmod only flips the read-only bit — grant Users NTFS
	// modify rights so the user-session tray can later toggle the state.
	_ = ensureUsersWritable(privacyFile, false)

	privacyMu.Lock()
	privacyEnabled = enabled
	privacyMu.Unlock()

	applyPrivacyTransition(enabled)

	// Notify server instantly via WebSocket command channel.
	SendOnCommandChannel(map[string]interface{}{
		"type":    "privacy_mode_changed",
		"enabled": enabled,
	})

	log.Printf("privacy: mode set to %v (by %s)", enabled, changedBy)
	return nil
}

// loadPrivacyState reads the current state from disk into memory.
// On first boot it also ensures privacy.json exists with privacyFileMode
// (0666 on Linux so the user-session tray can toggle the state without root
// privileges; 0644 on macOS where the tray uses the local socket).
func loadPrivacyState() {
	data, err := os.ReadFile(privacyFile)
	if err != nil {
		// File doesn't exist yet — privacy off by default.
		// Seed an empty state file. Errors are non-fatal (dir may not yet exist
		// on very first boot; privacy just stays OFF in memory).
		if os.IsNotExist(err) {
			_ = os.MkdirAll(configDir, 0755)
			empty, _ := json.MarshalIndent(privacyState{Enabled: false}, "", "  ")
			_ = os.WriteFile(privacyFile, empty, privacyFileMode)
			_ = os.Chmod(privacyFile, privacyFileMode) // bypass daemon umask
			_ = ensureUsersWritable(privacyFile, false)
		}
		return
	}
	// macOS: drop the group/world write bits older agents set (no-op
	// elsewhere, and never touches an admin-locked read-only file).
	hardenPrivacyFile()
	var state privacyState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("privacy: failed to parse %s: %v", privacyFile, err)
		return
	}
	privacyMu.Lock()
	privacyEnabled = state.Enabled
	privacyMu.Unlock()

	// Enforce ObliReach service state on startup.
	if state.Enabled {
		stopObliReachService()
	}
}

// watchPrivacyFile polls privacy.json every 2 seconds for changes made by the
// tray app. When the file changes, it updates the in-memory state and manages
// the ObliReach service.
func watchPrivacyFile(stopCh <-chan struct{}) {
	var lastModTime time.Time
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			info, err := os.Stat(privacyFile)
			if err != nil {
				continue
			}
			if info.ModTime().Equal(lastModTime) {
				continue
			}
			lastModTime = info.ModTime()

			data, err := os.ReadFile(privacyFile)
			if err != nil {
				continue
			}
			var state privacyState
			if err := json.Unmarshal(data, &state); err != nil {
				continue
			}

			privacyMu.Lock()
			changed := privacyEnabled != state.Enabled
			privacyEnabled = state.Enabled
			privacyMu.Unlock()

			if changed {
				applyPrivacyTransition(state.Enabled)
				// Notify server instantly via WS.
				SendOnCommandChannel(map[string]interface{}{
					"type":    "privacy_mode_changed",
					"enabled": state.Enabled,
				})
				log.Printf("privacy: file changed — mode now %v (by %s)", state.Enabled, state.ChangedBy)
			}
		}
	}
}

// ── ObliReach service control ───────────────────────────────────────────────────

// onPrivacyReleased runs when privacy mode is turned off (a variable so the
// tests observe it without touching the real service). The ObliReach manager
// installs a due update right away — verified, instead of restarting the old
// build that would then race its own self-update — or starts the installed
// build (oblireach_manager.go PrivacyReleased).
var onPrivacyReleased = func() { go obliReachMgr.PrivacyReleased() }

// applyPrivacyTransition acts on the privacy state just set (tray file or
// remote command).
func applyPrivacyTransition(enabled bool) {
	if enabled {
		stopObliReachService()
		usageStopAll() // the disk usage scans of the file explorer (usage_scan.go)
		obliReachMgr.Kick() // report privacy_deferred right away
		return
	}
	onPrivacyReleased()
}

func stopObliReachService() {
	if runtime.GOOS != "windows" {
		// Linux/macOS: ObliReach has no service unit — the agent supervises
		// it (oblireach_manager_unix.go): SIGTERM/SIGKILL every instance.
		obliReachUnixStop()
		return
	}
	// Stop the service and disable auto-start so it stays down across reboots.
	_ = newCmd("sc", "stop", "ObliReachAgent").Run()
	if err := newCmd("sc", "config", "ObliReachAgent", "start=", "disabled").Run(); err != nil {
		log.Printf("privacy: failed to disable ObliReachAgent: %v", err)
	}
}

// (Turning privacy mode off no longer runs `sc config start= auto` +
// `sc start` here: the ObliReach manager does it — PrivacyReleased — so the
// old build is not restarted when an update is due.)
