//go:build windows

package main

import (
	"io"
	"os"
	"testing"
	"time"
)

// TestPipeShellRealCmd starts a real cmd.exe over the pipe fallback and
// checks a round trip: write a command, read its output. Opt-in — it spawns
// a real process — mirrors OBLIANCE_TEST_CONPTY's pattern in
// tunnel_shell_integration_windows_test.go, run with:
//
//	OBLIANCE_TEST_PIPE_SHELL=1 go test -run TestPipeShellRealCmd -v .
func TestPipeShellRealCmd(t *testing.T) {
	if os.Getenv("OBLIANCE_TEST_PIPE_SHELL") == "" {
		t.Skip("set OBLIANCE_TEST_PIPE_SHELL=1 to start a real cmd.exe over the pipe fallback")
	}
	sh, err := newPipeShellSession("cmd", 0)
	if err != nil {
		t.Fatalf("newPipeShellSession: %v", err)
	}
	defer sh.Close()

	if got := sh.PtyMode(); got != "pipe" {
		t.Errorf("PtyMode() = %q, want pipe", got)
	}

	if _, err := sh.Write([]byte("echo OBLIANCE_PIPE_SHELL_OK\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		var all []byte
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			n, err := sh.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
				if len(all) > 0 && contains(all, "OBLIANCE_PIPE_SHELL_OK") && contains(all[indexOf(all, "OBLIANCE_PIPE_SHELL_OK")+len("OBLIANCE_PIPE_SHELL_OK"):], "OBLIANCE_PIPE_SHELL_OK") {
					// The echoed command line itself plus its output both
					// contain the marker; second occurrence = the command
					// actually ran, not just got echoed back.
					done <- string(all)
					return
				}
			}
			if err == io.EOF {
				break
			}
		}
		done <- string(all)
	}()

	select {
	case out := <-done:
		if !contains([]byte(out), "OBLIANCE_PIPE_SHELL_OK") {
			t.Errorf("did not see the marker in output: %q", out)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("timed out waiting for shell output")
	}

	if err := sh.Resize(80, 24); err != nil {
		t.Errorf("Resize should be a harmless no-op, got: %v", err)
	}
}

func contains(b []byte, s string) bool { return indexOf(b, s) >= 0 }

func indexOf(b []byte, s string) int {
	n, m := len(b), len(s)
	for i := 0; i+m <= n; i++ {
		if string(b[i:i+m]) == s {
			return i
		}
	}
	return -1
}
