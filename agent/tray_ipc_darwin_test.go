//go:build darwin

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/obliance/agent/internal/trayipc"
)

// The kernel peer credentials of a real Unix socket connection identify the
// calling user (here: the test process itself).
func TestPeerUIDRealSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "obl-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock") // short path: sun_path is 104 bytes
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		uid uint32
		err error
	}
	got := make(chan result, 1)
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			got <- result{err: err}
			return
		}
		defer c.Close()
		uid, err := peerUID(c)
		got <- result{uid, err}
		// Answer like the daemon so Call() completes.
		trayipc.Serve(c, uid, trayipc.Console{UID: uid, Known: true}, fakeIPCBackend{})
	}()

	resp, err := trayipc.Call(sock, trayipc.Request{Op: trayipc.OpStatus}, 5*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !resp.OK {
		t.Fatalf("status refused: %+v", resp)
	}
	r := <-got
	if r.err != nil {
		t.Fatalf("peerUID: %v", r.err)
	}
	if r.uid != uint32(os.Getuid()) {
		t.Fatalf("peerUID = %d, want %d", r.uid, os.Getuid())
	}
}

type fakeIPCBackend struct{}

func (fakeIPCBackend) Privacy() (bool, bool)         { return false, false }
func (fakeIPCBackend) SetPrivacy(bool, uint32) error { return nil }

func TestConsoleUserKnown(t *testing.T) {
	c := consoleUser()
	if !c.Known {
		t.Skip("/dev/console not stat-able here")
	}
}

func TestHardenPrivacyFile(t *testing.T) {
	saved := privacyFile
	defer func() { privacyFile = saved }()
	privacyFile = filepath.Join(t.TempDir(), "privacy.json")

	if err := os.WriteFile(privacyFile, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ in, want os.FileMode }{
		{0666, 0644}, // legacy world-writable -> 0644
		{0664, 0644},
		{0644, 0644},
		{0444, 0444}, // admin lock is kept
	} {
		if err := os.Chmod(privacyFile, c.in); err != nil {
			t.Fatal(err)
		}
		hardenPrivacyFile()
		info, err := os.Stat(privacyFile)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != c.want {
			t.Errorf("hardenPrivacyFile(%o) -> %o, want %o", c.in, info.Mode().Perm(), c.want)
		}
	}
}
