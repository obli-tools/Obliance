package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadAgentVersionOrder(t *testing.T) {
	dir := t.TempDir()
	oldStatus, oldVersion := statusFile, versionFile
	statusFile = filepath.Join(dir, "status.json")
	versionFile = filepath.Join(dir, "config.json")
	t.Cleanup(func() { statusFile, versionFile = oldStatus, oldVersion })

	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if v := readAgentVersion(); v != "?" {
		t.Fatalf("no file: got %q, want ?", v)
	}
	// Old agent: only config.json.
	write(versionFile, `{"apiKey":"k","agentVersion":"4.5.87"}`)
	if v := readAgentVersion(); v != "4.5.87" {
		t.Fatalf("config.json fallback: got %q", v)
	}
	// New agent: status.json wins.
	write(statusFile, `{"agentVersion":"4.5.88"}`)
	if v := readAgentVersion(); v != "4.5.88" {
		t.Fatalf("status.json first: got %q", v)
	}
	// Empty / corrupt status.json falls back to config.json.
	write(statusFile, `{"agentVersion":""}`)
	if v := readAgentVersion(); v != "4.5.87" {
		t.Fatalf("empty status: got %q", v)
	}
	write(statusFile, `not json`)
	if v := readAgentVersion(); v != "4.5.87" {
		t.Fatalf("corrupt status: got %q", v)
	}
	// New agent, config.json unreadable by the tray user: status.json only,
	// the permission error is ignored.
	write(statusFile, `{"agentVersion":"4.5.88"}`)
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if err := os.Chmod(versionFile, 0o000); err != nil {
			t.Fatal(err)
		}
		if v := readAgentVersion(); v != "4.5.88" {
			t.Fatalf("unreadable config.json: got %q", v)
		}
		if err := os.Remove(statusFile); err != nil {
			t.Fatal(err)
		}
		if v := readAgentVersion(); v != "?" {
			t.Fatalf("unreadable config.json, no status: got %q", v)
		}
	}
}
