//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Symbolic links are never followed nor counted; a folder that cannot be
// read is counted as an error; a file with two hard links is counted once.
func TestUsageScanUnixLinksDeniedHardlinks(t *testing.T) {
	root := usageTree(t)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "huge"), []byte(strings.Repeat("y", 100000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "huge"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "a", "b", "big"), filepath.Join(root, "c", "big-again")); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(root, "denied")
	if err := os.MkdirAll(filepath.Join(denied, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(denied, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	s := newUsageScan(root, time.Now())
	s.begin()
	if st := usageWait(t, s); st != "done" {
		t.Fatalf("state %s", st)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rootNode.size != 4450 || s.rootNode.files != 4 {
		t.Fatalf("size %d files %d: a link, the hard link or the denied folder was counted", s.rootNode.size, s.rootNode.files)
	}
	if s.skippedN != 2 {
		t.Fatalf("links skipped: %d", s.skippedN)
	}
	dn := s.findLocked(denied)
	if dn == nil || !dn.denied || s.errorsN < 1 {
		t.Fatalf("denied folder: %+v", dn)
	}
}
