//go:build !windows

package main

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The real shell in a real PTY (newShellSession, as the terminal tunnel starts
// it): bash through the agent's rcfile reports its folder with OSC 7, at the
// first prompt and after a cd. Opt-in, as root (the rcfile is trusted only
// when root owns it): OBLIANCE_TEST_PTY=1 go test -run TestShellIntegrationPTY .
func TestShellIntegrationPTY(t *testing.T) {
	if os.Getenv("OBLIANCE_TEST_PTY") == "" {
		t.Skip("set OBLIANCE_TEST_PTY=1 (as root) to start a real shell in a PTY")
	}
	if os.Geteuid() != 0 {
		t.Skip("root only: the rcfile must be root's")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()
	if err := os.Chmod(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	odd := t.TempDir() + "/my dir é#%"
	if err := os.Mkdir(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	sh, err := newShellSession(120, 30, "ssh", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if _, err := os.Stat(configDir + "/" + bashIntegrationFile); err != nil {
		t.Fatalf("the rcfile was not written: %v", err)
	}
	var mu sync.Mutex
	var out strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sh.Read(buf)
			mu.Lock()
			out.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	wait := func(what string) string {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			s := out.String()
			mu.Unlock()
			if strings.Contains(s, what) {
				return s
			}
			time.Sleep(100 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("no %q in %q", what, out.String())
		return ""
	}
	wait("\x1b]7;file://")
	sh.Write([]byte("cd '" + odd + "'\r"))
	s := wait("/my%20dir%20%C3%A9%23%25\x1b\\")
	if strings.Contains(s, "__obliance") || strings.Contains(s, "command not found") || strings.Contains(s, "syntax error") {
		t.Errorf("the rcfile showed or failed: %q", s)
	}
}
