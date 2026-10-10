package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withIdentityDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	identityDirOverride, identitySkipTrustTest = dir, true
	t.Cleanup(func() {
		identityDirOverride, identitySkipTrustTest = "", false
		devIdentity = &deviceIdentityState{}
	})
	devIdentity = &deviceIdentityState{}
	return dir
}

func TestIdentityLooksCloned(t *testing.T) {
	base := identityFingerprint{OS: "a", HW: "b", Disk: "c"}
	cases := []struct {
		name   string
		cur    identityFingerprint
		hwJunk bool
		want   bool
	}{
		{"same", base, false, false},
		{"os changed", identityFingerprint{OS: "x", HW: "b", Disk: "c"}, false, true},
		{"hw changed", identityFingerprint{OS: "a", HW: "x", Disk: "c"}, false, true},
		{"disk changed, good hw", identityFingerprint{OS: "a", HW: "b", Disk: "x"}, false, false},
		{"disk changed, junk hw", identityFingerprint{OS: "a", HW: "b", Disk: "x"}, true, true},
		{"unknown now", identityFingerprint{}, true, false},
	}
	for _, c := range cases {
		if got := identityLooksCloned(base, c.cur, c.hwJunk); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if identityLooksCloned(identityFingerprint{}, base, true) {
		t.Error("empty stored fingerprint must never count as a change")
	}
}

func TestHardwareUUIDJunk(t *testing.T) {
	for _, u := range []string{"", "nope", "00000000-0000-0000-0000-000000000000", "03000200-0400-0500-0006-000700080009", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"} {
		if !oidHardwareUUIDIsJunk(u) {
			t.Errorf("%q should be junk", u)
		}
	}
	if oidHardwareUUIDIsJunk("4c4c4544-0042-3510-8052-b4c04f4e3732") {
		t.Error("real Dell UUID flagged junk")
	}
}

func TestSharedIdentityFirstInstall(t *testing.T) {
	withIdentityDir(t)
	legacy := "11111111-2222-4333-8444-555555555555"
	switched := ""
	// No ID stored: the shared ID is used at once, the legacy one claimed.
	cur, done := initDeviceIdentity(false, "", func() string { return legacy }, "test/1", func(id string) { switched = id })
	id, err := readIdentityFile()
	if err != nil || id == nil {
		t.Fatalf("shared file not created: %v", err)
	}
	if cur != id.DeviceID || !done || currentDeviceUUID() != id.DeviceID {
		t.Fatalf("first install must use the shared ID at once: cur=%s done=%v", cur, done)
	}
	h := http.Header{}
	applyIdentityHeaders(h)
	if h.Get(IdentityHeaderTarget) != id.DeviceID || h.Get(IdentityHeaderPrevious) != legacy {
		t.Fatalf("first install headers: %v", h)
	}
	if !acceptIdentityAck(id.DeviceID) || switched != "" {
		t.Fatalf("ack of the ID already in use: switched=%q", switched)
	}
	h = http.Header{}
	applyIdentityHeaders(h)
	if h.Get(IdentityHeaderTarget) != "" {
		t.Fatal("headers still sent after ack")
	}
}

func TestSharedIdentityCreateAndMigrate(t *testing.T) {
	withIdentityDir(t)
	legacy := "11111111-2222-4333-8444-555555555555"
	switched := ""
	// An agent already enrolled under its legacy ID (stored, not v2) keeps it
	// until the server acknowledges the switch.
	cur, done := initDeviceIdentity(false, legacy, func() string { return legacy }, "test/1", func(id string) { switched = id })
	if cur != legacy || done {
		t.Fatalf("existing install must stay on legacy until ack: cur=%s done=%v", cur, done)
	}
	id, err := readIdentityFile()
	if err != nil || id == nil {
		t.Fatalf("shared file not created: %v", err)
	}

	h := http.Header{}
	applyIdentityHeaders(h)
	if h.Get(IdentityHeaderTarget) != id.DeviceID || h.Get(IdentityHeaderPrevious) != legacy {
		t.Fatalf("headers: %v", h)
	}
	if acceptIdentityAck("99999999-2222-4333-8444-555555555555") {
		t.Fatal("ack for another ID accepted")
	}
	if !acceptIdentityAck(id.DeviceID) || switched != id.DeviceID || currentDeviceUUID() != id.DeviceID {
		t.Fatalf("switch failed: switched=%s current=%s", switched, currentDeviceUUID())
	}
	h = http.Header{}
	applyIdentityHeaders(h)
	if h.Get(IdentityHeaderTarget) != "" {
		t.Fatal("headers still sent after ack")
	}

	// Next start with identityV2: nothing pending.
	devIdentity = &deviceIdentityState{}
	cur, done = initDeviceIdentity(true, id.DeviceID, func() string { t.Fatal("legacy resolver called"); return "" }, "test/1", nil)
	if cur != id.DeviceID || !done {
		t.Fatalf("restart: cur=%s done=%v", cur, done)
	}
}

func TestSharedIdentityRegenAndClone(t *testing.T) {
	dir := withIdentityDir(t)
	first := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if err := writeIdentityFile(&sharedIdentity{DeviceID: first, Reason: identityReasonCreated}); err != nil {
		t.Fatal(err)
	}
	cur, done := initDeviceIdentity(true, first, nil, "test/1", nil)
	if cur != first || !done {
		t.Fatalf("cur=%s done=%v", cur, done)
	}

	// Regen script: new ID, old one in previousIds -> claim [current, previous...].
	second := "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	data := `{"format":1,"deviceId":"` + strings.ToUpper(second) + `","previousIds":["` + first + `"],"reason":"regenerated"}`
	if err := os.WriteFile(filepath.Join(dir, identityFileName), append([]byte{0xEF, 0xBB, 0xBF}, data...), 0644); err != nil {
		t.Fatal(err)
	}
	devIdentity.modTime = devIdentity.modTime.Add(-1) // force re-read
	checkSharedIdentityOnce()
	h := http.Header{}
	applyIdentityHeaders(h)
	if h.Get(IdentityHeaderTarget) != second || h.Get(IdentityHeaderPrevious) != first {
		t.Fatalf("regen headers: %v", h)
	}

	// Clone detected: new target, no claims at all.
	third := "cccccccc-dddd-4eee-8fff-000000000000"
	if err := writeIdentityFile(&sharedIdentity{DeviceID: third, Reason: identityReasonClone}); err != nil {
		t.Fatal(err)
	}
	devIdentity.modTime = devIdentity.modTime.Add(-1)
	checkSharedIdentityOnce()
	h = http.Header{}
	applyIdentityHeaders(h)
	if h.Get(IdentityHeaderTarget) != third || h.Get(IdentityHeaderPrevious) != "" {
		t.Fatalf("clone headers: %v", h)
	}
}

func TestSharedIdentitySeedsFromV1Override(t *testing.T) {
	dir := withIdentityDir(t)
	ov := "dddddddd-eeee-4fff-8000-111111111111"
	if err := os.WriteFile(filepath.Join(dir, identityOverrideName), []byte(ov+"\r\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// The v1 resolver already returns the override: nothing to migrate.
	cur, done := initDeviceIdentity(false, "", func() string { return ov }, "test/1", nil)
	if cur != ov || !done {
		t.Fatalf("cur=%s done=%v", cur, done)
	}
	id, _ := readIdentityFile()
	if id == nil || id.DeviceID != ov || id.Reason != identityReasonOverride {
		t.Fatalf("file: %+v", id)
	}
}

func TestIdentityLock(t *testing.T) {
	withIdentityDir(t)
	unlock, err := lockIdentity()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	unlock2, err := lockIdentity()
	if err != nil {
		t.Fatal("lock not released")
	}
	unlock2()
}
