package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withPrivacyFixture points privacy.json at a temp file, sets the in-memory
// state and replaces the release hook (never the real ObliReach service).
func withPrivacyFixture(t *testing.T, enabled bool) chan struct{} {
	t.Helper()
	savedFile, savedHook := privacyFile, onPrivacyReleased
	privacyMu.Lock()
	savedEnabled := privacyEnabled
	privacyEnabled = enabled
	privacyMu.Unlock()
	t.Cleanup(func() {
		privacyFile, onPrivacyReleased = savedFile, savedHook
		privacyMu.Lock()
		privacyEnabled = savedEnabled
		privacyMu.Unlock()
	})
	privacyFile = filepath.Join(t.TempDir(), "privacy.json")
	released := make(chan struct{}, 8)
	onPrivacyReleased = func() { released <- struct{}{} }
	return released
}

// The tray turns privacy mode off (privacy.json) → the ObliReach manager's
// release runs (it installs a due update or starts ObliReach) — no more
// direct restart of the old build.
func TestPrivacyWatcherReleaseRunsManager(t *testing.T) {
	released := withPrivacyFixture(t, true)
	if err := os.WriteFile(privacyFile, []byte(`{"enabled":false,"changedBy":"user"}`), 0600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go watchPrivacyFile(stop)
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatalf("privacy file OFF did not reach the ObliReach manager")
	}
	if IsPrivacyMode() {
		t.Fatalf("privacy mode still on in memory")
	}
	// No further change → no second release.
	select {
	case <-released:
		t.Fatalf("released twice without a change")
	case <-time.After(2500 * time.Millisecond):
	}
}

// The remote command (disable_privacy_mode) takes the same path.
func TestSetPrivacyModeOffRunsManager(t *testing.T) {
	released := withPrivacyFixture(t, true)
	if err := SetPrivacyMode(false, "remote"); err != nil {
		t.Fatalf("SetPrivacyMode: %v", err)
	}
	select {
	case <-released:
	default:
		t.Fatalf("remote OFF did not reach the ObliReach manager")
	}
	if IsPrivacyMode() {
		t.Fatalf("privacy mode still on in memory")
	}
}
