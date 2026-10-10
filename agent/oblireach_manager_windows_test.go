//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The staging folder is created atomically with a protected DACL (SYSTEM +
// Administrators only, nothing inherited) and cleaned up by exact name only.
func TestObliReachWindowsStagingFolder(t *testing.T) {
	saved := configDir
	configDir = t.TempDir()
	defer func() { configDir = saved }()

	o := &winObliReachOps{}
	s, err := o.Stage("oblireach-agent.msi")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !strings.EqualFold(filepath.Dir(s.Dir), configDir) || filepath.Base(s.Path) != "oblireach-agent.msi" {
		t.Fatalf("unexpected stage %+v", s)
	}
	sd, err := windows.GetNamedSecurityInfo(s.Dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	sddl := sd.String()
	if !strings.Contains(sddl, "D:P") || strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") {
		t.Fatalf("staging DACL not private: %s", sddl)
	}
	// SYSTEM / elevated administrators may write there; a plain user may not.
	werr := os.WriteFile(s.Path, []byte("x"), 0600)
	if windows.GetCurrentProcessToken().IsElevated() {
		if werr != nil {
			t.Fatalf("elevated write into staging: %v", werr)
		}
	} else if werr == nil {
		t.Fatalf("a non-elevated user could write into the private staging folder")
	}

	// Failure: MSI removed, folder (logs) kept.
	o.FinishStage(s, true)
	if _, err := os.Stat(s.Path); !os.IsNotExist(err) {
		t.Fatalf("MSI not removed")
	}
	if _, err := os.Stat(s.Dir); err != nil {
		t.Fatalf("log folder removed on failure")
	}
	// Anything that is not one of our staging folders is never removed.
	outside := filepath.Join(t.TempDir(), "oblireach-staging-0123456789abcdef")
	_ = os.MkdirAll(outside, 0755)
	o.DiscardStaging(outside)
	foreign := filepath.Join(configDir, "something-else")
	_ = os.MkdirAll(foreign, 0755)
	o.DiscardStaging(foreign)
	for _, p := range []string{outside, foreign} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("DiscardStaging removed a foreign folder %s", p)
		}
	}
	o.DiscardStaging(s.Dir)
	if _, err := os.Stat(s.Dir); !os.IsNotExist(err) {
		if !windows.GetCurrentProcessToken().IsElevated() {
			// Test-environment limit, not a production issue: the agent runs
			// as SYSTEM, which the DACL grants full control. A NON-elevated
			// test user is denied listing the folder, and os.RemoveAll of Go
			// < 1.22 (the nt6 build, Go 1.20) gives up on it where newer Go
			// deletes it. Hand the folder back to its owner so t.TempDir's
			// cleanup can remove it, and skip the remaining assertion.
			releaseStagingForCleanup(t, s.Dir)
			t.Skipf("non-elevated run with %s: os.RemoveAll cannot delete the SYSTEM/Administrators-only folder (run elevated to cover this step)", runtime.Version())
		}
		t.Fatalf("staging folder not discarded")
	}
}

// releaseStagingForCleanup resets the folder's DACL to "owner full control"
// (the creator owns it and may always rewrite its DACL) and removes it.
func releaseStagingForCleanup(t *testing.T, dir string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;OW)")
	if err != nil {
		t.Logf("cleanup SDDL: %v", err)
		return
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Logf("cleanup DACL: %v", err)
		return
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Logf("cleanup SetNamedSecurityInfo: %v", err)
		return
	}
	_ = os.RemoveAll(dir)
}
