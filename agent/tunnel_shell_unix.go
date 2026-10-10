//go:build !windows

package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

type unixShell struct {
	ptmx *os.File
	cmd  *exec.Cmd
}

// newShellSession spawns a login shell attached to a pseudo-terminal (bash:
// through the agent's rcfile, which reads the login files and reports the
// working directory; tunnel_shell_integration.go).
// cols/rows set the initial terminal dimensions so the first paint is correct.
// The sessionToken and the trailing int are accepted for signature
// compatibility with the Windows build and the (now-removed) tmux wrapper
// — they are intentionally unused.
func newShellSession(cols, rows uint16, shellCmd string, _ string, _ int) (shellSession, error) {
	var sh string
	var shArgs []string
	if shellCmd == "powershell" {
		if _, err := exec.LookPath("pwsh"); err == nil {
			sh = "pwsh"
			shArgs = []string{"-NoLogo", "-NoExit"}
		}
	}
	if sh == "" {
		sh = "/bin/bash"
		if _, err := exec.LookPath(sh); err != nil {
			sh = "/bin/sh"
			// /bin/sh on FreeBSD does not support --login, use -l
			shArgs = []string{"-l"}
		} else {
			shArgs = []string{"--login"}
			// The shell reports its folder at each prompt (OSC 7: the
			// Oblireach Desktop sends a dropped file there): the agent's
			// rcfile reads the login files, then adds it
			// (tunnel_shell_integration.go). Any problem: --login, as before.
			if rc, err := ensureBashIntegration(); err == nil {
				shArgs = []string{"--rcfile", rc, "-i"}
			} else {
				log.Printf("ssh shell: %v (plain login shell)", err)
			}
		}
	}

	cmd := newCmd(sh, shArgs...)
	// Build env: inherit parent, strip any TMOUT (bash idle-logout) that would
	// silently kill the session after N seconds of inactivity, then append ours.
	baseEnv := os.Environ()
	env := make([]string, 0, len(baseEnv)+2)
	for _, e := range baseEnv {
		if len(e) >= 6 && e[:6] == "TMOUT=" {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "TERM=xterm-256color", "TMOUT=0")
	cmd.Env = env

	ws := &pty.Winsize{Cols: cols, Rows: rows}
	ptmx, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return nil, err
	}
	return &unixShell{ptmx: ptmx, cmd: cmd}, nil
}

func (s *unixShell) Read(p []byte) (int, error)  { return s.ptmx.Read(p) }
func (s *unixShell) Write(p []byte) (int, error) { return s.ptmx.Write(p) }

func (s *unixShell) Resize(cols, rows uint16) error {
	return pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

func (s *unixShell) PtyMode() string { return "pty" }

func (s *unixShell) Close() error {
	s.ptmx.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return nil
}
