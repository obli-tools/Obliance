//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Junctions and symbolic links are never walked into (nor counted), a
// folder that cannot be read is counted as an error, never fatal.
func TestUsageScanWindowsLinksAndDenied(t *testing.T) {
	root := usageTree(t)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "huge"), []byte(strings.Repeat("y", 100000)), 0o644); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, elsewhere).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	symlinked := os.Symlink(elsewhere, filepath.Join(root, "symlink")) == nil // needs the right to create links
	denied := filepath.Join(root, "denied")
	if err := os.MkdirAll(filepath.Join(denied, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(denied, "inner", "secret"), []byte("zzz"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", denied, "/deny", "*S-1-1-0:(OI)(CI)(RX)").CombinedOutput(); err != nil {
		t.Skipf("icacls: %v %s", err, out)
	}
	defer exec.Command("icacls", denied, "/remove:d", "*S-1-1-0").Run()

	s := newUsageScan(root, time.Now())
	s.begin()
	if st := usageWait(t, s); st != "done" {
		t.Fatalf("state %s", st)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rootNode
	if r.size != 4450 {
		t.Fatalf("a link or the denied folder was counted: %d", r.size)
	}
	if s.findLocked(junction) != nil {
		t.Fatalf("a junction is not a node")
	}
	want := int64(1)
	if symlinked {
		want = 2
	}
	if s.skippedN != want {
		t.Fatalf("links skipped: %d, want %d", s.skippedN, want)
	}
	dn := s.findLocked(denied)
	if dn == nil || !dn.denied || !dn.done || s.errorsN < 1 || !r.done {
		t.Fatalf("denied folder: %+v errors=%d", dn, s.errorsN)
	}
}

func TestUsageLongPathAndCluster(t *testing.T) {
	long := `C:\` + strings.Repeat(`abcdefghij\`, 30)
	if got := usageLongPath(long); !strings.HasPrefix(got, `\\?\C:\`) {
		t.Errorf("long path: %s", got)
	}
	if got := usageLongPath(`\\srv\share\` + strings.Repeat("a", 260)); !strings.HasPrefix(got, `\\?\UNC\srv\share\`) {
		t.Errorf("long UNC path: %s", got)
	}
	if got := usageLongPath(`C:\short`); got != `C:\short` {
		t.Errorf("short path changed: %s", got)
	}
	c := usageClusterSize(os.TempDir())
	if c < 512 || c%512 != 0 {
		t.Errorf("cluster size %d", c)
	}
	if usageRoundUp(1, 4096) != 4096 || usageRoundUp(0, 4096) != 0 || usageRoundUp(4097, 4096) != 8192 {
		t.Errorf("round up")
	}
}
