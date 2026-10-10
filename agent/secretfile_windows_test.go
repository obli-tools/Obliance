//go:build windows

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// daclSDDL returns the D: part of the file's security descriptor.
func daclSDDL(t *testing.T, p string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo %s: %v", p, err)
	}
	s := sd.String()
	if i := strings.Index(s, "D:"); i >= 0 {
		return s[i:]
	}
	t.Fatalf("no DACL in %q", s)
	return ""
}

// aceSIDs lists the trustee of every ACE in an SDDL DACL.
var aceRe = regexp.MustCompile(`\(([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);([^)]*)\)`)

func assertSystemAdminsOnly(t *testing.T, p string) {
	t.Helper()
	d := daclSDDL(t, p)
	if !strings.HasPrefix(d, "D:P") {
		t.Fatalf("%s: DACL not protected: %s", filepath.Base(p), d)
	}
	aces := aceRe.FindAllStringSubmatch(d, -1)
	if len(aces) == 0 {
		t.Fatalf("%s: empty DACL: %s", filepath.Base(p), d)
	}
	for _, a := range aces {
		if a[1] != "A" || (a[6] != "SY" && a[6] != "BA") || strings.Contains(a[2], "ID") {
			t.Fatalf("%s: unexpected ACE %s in %s", filepath.Base(p), a[0], d)
		}
	}
	for _, bad := range []string{";BU)", ";WD)", ";AU)", ";IU)", ";BG)"} {
		if strings.Contains(d, bad) {
			t.Fatalf("%s: DACL still grants %s: %s", filepath.Base(p), bad, d)
		}
	}
}

// canReplaceSecretFiles: replacing / rewriting a protected file needs
// SYSTEM or an elevated Administrators token (that is the point); a
// non-elevated test run can only create one.
func canReplaceSecretFiles() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func TestWriteSecretFileProtectedDACL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := writeSecretFile(p, []byte(`{"apiKey":"k"}`)); err != nil {
		t.Fatalf("writeSecretFile (create): %v", err)
	}
	assertSystemAdminsOnly(t, p)
	assertNoTempLeft(t, dir)

	if !canReplaceSecretFiles() {
		t.Skip("replace case needs an elevated token (non-elevated users are locked out, as intended)")
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != `{"apiKey":"k"}` {
		t.Fatalf("read back as admin: %q, %v", b, err)
	}

	// Replacing an existing file that carries the old Users:(M) grant.
	if err := ensureUsersWritable(p, false); err != nil {
		t.Logf("icacls grant (setup): %v", err)
	}
	if err := writeSecretFile(p, []byte(`{"apiKey":"k2"}`)); err != nil {
		t.Fatalf("writeSecretFile (replace): %v", err)
	}
	assertSystemAdminsOnly(t, p)
	assertNoTempLeft(t, dir)
}

func TestProtectSecretFileStripsUsersGrant(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"apiKey":"k"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ensureUsersWritable(p, false); err != nil {
		t.Fatalf("icacls grant (setup): %v", err)
	}
	if d := daclSDDL(t, p); !strings.Contains(d, ";BU)") {
		t.Fatalf("setup: expected a BUILTIN\\Users ACE, got %s", d)
	}
	if err := protectSecretFile(p); err != nil {
		t.Fatalf("protectSecretFile: %v", err)
	}
	assertSystemAdminsOnly(t, p)
	if err := hardenSecretFile(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatalf("hardenSecretFile on a missing file must be a no-op: %v", err)
	}
}
