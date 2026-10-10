package main

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The real shells in a real ConPTY (newShellSession, as the terminal tunnel
// starts them) report their folder with OSC 9;9: at the first prompt, and
// after a cd. Opt-in (it starts cmd.exe and powershell.exe):
// OBLIANCE_TEST_CONPTY=1 go test -run TestShellIntegrationConPTY .
func TestShellIntegrationConPTY(t *testing.T) {
	if os.Getenv("OBLIANCE_TEST_CONPTY") == "" {
		t.Skip("set OBLIANCE_TEST_CONPTY=1 to start real shells in a ConPTY")
	}
	if err := conptyAvailable(); err != nil {
		t.Skip(err)
	}
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	// As the service: no standard handles (the shell would write to this
	// test's pipes instead of its pseudo-console: newShellSession does not
	// set STARTF_USESTDHANDLES, a service has none to give).
	for _, h := range []uint32{windows.STD_INPUT_HANDLE, windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		old, _ := windows.GetStdHandle(h)
		_ = windows.SetStdHandle(h, 0)
		defer windows.SetStdHandle(h, old)
	}
	odd := t.TempDir() + `\my dir é`
	if err := os.Mkdir(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ kind, cd, cd2 string }{{"cmd", `cd /d ` + win, `cd /d "` + odd + `"`}, {"powershell", `Set-Location ` + win, `Set-Location '` + odd + `'`}} {
		t.Run(c.kind, func(t *testing.T) {
			sh, err := newShellSession(120, 30, c.kind, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			defer sh.Close()
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
				deadline := time.Now().Add(20 * time.Second)
				for time.Now().Before(deadline) {
					mu.Lock()
					s := out.String()
					mu.Unlock()
					if strings.Contains(strings.ToLower(s), strings.ToLower(what)) {
						return s
					}
					time.Sleep(100 * time.Millisecond)
				}
				mu.Lock()
				defer mu.Unlock()
				t.Fatalf("%s: no %q in %q", c.kind, what, out.String())
				return ""
			}
			wait("\x1b]9;9;") // the first prompt
			sh.Write([]byte(c.cd + "\r"))
			s := wait("\x1b]9;9;" + win + "\x1b\\") // after the cd
			sh.Write([]byte(c.cd2 + "\r"))
			s = wait("\x1b]9;9;" + odd + "\x1b\\") // a space, a non-ASCII letter (UTF-8 out of the ConPTY)
			for _, bad := range []string{"__oblianceP", "At line:", "ParserError", "Exception"} {
				if strings.Contains(s, bad) {
					t.Errorf("%s: %q in the terminal (the wrapper failed or showed): %q", c.kind, bad, s)
				}
			}
		})
	}
}
