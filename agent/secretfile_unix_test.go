//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// canReplaceSecretFiles: on Unix the owner of the temp dir can always
// replace the 0600 file (rename is governed by the directory).
func canReplaceSecretFiles() bool { return true }

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi.Mode().Perm()
}

func TestSaveConfigIs0600AndStatusIs0644(t *testing.T) {
	useTempConfigDir(t)
	// A config.json left world-readable by an older agent...
	if err := os.WriteFile(configFile, []byte(`{"apiKey":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(&Config{ServerURL: "https://x", APIKey: "k"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	// ...is replaced by a 0600 one.
	if m := perm(t, configFile); m != 0o600 {
		t.Fatalf("config.json mode = %o, want 600", m)
	}
	if err := writeAgentStatus("1.0.0"); err != nil {
		t.Fatalf("writeAgentStatus: %v", err)
	}
	if m := perm(t, statusFile); m != 0o644 {
		t.Fatalf("status.json mode = %o, want 644", m)
	}
}

func TestWriteSecretFileIgnoresUmaskAndOldMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(p, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o666)
	if err := writeSecretFile(p, []byte("y")); err != nil {
		t.Fatalf("writeSecretFile: %v", err)
	}
	if m := perm(t, p); m != 0o600 {
		t.Fatalf("mode = %o, want 600", m)
	}
	if b, _ := os.ReadFile(p); string(b) != "y" {
		t.Fatalf("content = %q", b)
	}
}

func TestWriteSecretFileReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := writeSecretFile(p, []byte("secret")); err != nil {
		t.Fatalf("writeSecretFile: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target was written through: %q", b)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.json should be a regular 0600 file, got %v (%v)", fi, err)
	}
}

func TestHardenSecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := hardenSecretFile(p); err != nil {
		t.Fatalf("missing file must be a no-op: %v", err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o644)
	if err := hardenSecretFile(p); err != nil {
		t.Fatalf("hardenSecretFile: %v", err)
	}
	if m := perm(t, p); m != 0o600 {
		t.Fatalf("mode = %o, want 600", m)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err == nil {
		if err := hardenSecretFile(link); err == nil {
			t.Fatal("symlink must be refused")
		}
	}
}
