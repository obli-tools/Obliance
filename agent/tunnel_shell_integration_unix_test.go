//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The rcfile is written, rewritten when it differs, and trusted only when
// nobody but its owner can change it (the agent: root; here: this user).
func TestEnsureBashIntegrationIn(t *testing.T) {
	me := uint32(os.Getuid())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := ensureBashIntegrationIn(dir, me)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, bashIntegrationFile) {
		t.Fatalf("path %s", p)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Lstat(p)
	if string(b) != bashIntegration || fi.Mode().Perm() != 0o644 {
		t.Fatalf("content or mode (%v) wrong", fi.Mode())
	}
	// Changed by hand: rewritten.
	os.WriteFile(p, []byte("echo changed\n"), 0o644)
	if _, err := ensureBashIntegrationIn(dir, me); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != bashIntegration {
		t.Fatal("a changed rcfile must be rewritten")
	}
	// A link in its place: replaced by the file, the link's target untouched.
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("keep\n"), 0o644)
	os.Remove(p)
	if err := os.Symlink(target, p); err != nil {
		t.Skip("no symlinks here")
	}
	if _, err := ensureBashIntegrationIn(dir, me); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(p); !fi.Mode().IsRegular() {
		t.Fatal("the link must be replaced by a regular file")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatal("the link's target must never be written")
	}
	// A folder others can write to, or another owner: refused (plain --login).
	os.Chmod(dir, 0o775)
	if _, err := ensureBashIntegrationIn(dir, me); err == nil {
		t.Fatal("a group-writable folder must be refused")
	}
	os.Chmod(dir, 0o755)
	if _, err := ensureBashIntegrationIn(dir, me+1); err == nil {
		t.Fatal("a folder of another owner must be refused")
	}
	if _, err := ensureBashIntegrationIn(filepath.Join(dir, "missing"), me); err == nil {
		t.Fatal("a missing folder must be refused")
	}
	if err := checkRootOnly(p, me+1, false); err == nil {
		t.Fatal("a file of another owner must not be trusted")
	}
	os.Chmod(p, 0o664)
	if err := checkRootOnly(p, me, false); err == nil {
		t.Fatal("a group-writable file must not be trusted")
	}
	if _, err := ensureBashIntegrationIn(dir, me); err != nil {
		t.Fatal(err)
	}
	if err := checkRootOnly(p, me, false); err != nil {
		t.Fatalf("rewritten with the right mode: %v", err)
	}
	// Nothing left behind.
	es, _ := os.ReadDir(dir)
	if len(es) != 1 {
		t.Fatalf("temporary files left: %v", es)
	}
}
