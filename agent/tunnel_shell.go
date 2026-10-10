package main

// shellSession abstracts a platform-specific PTY (Unix) or ConPTY (Windows)
// shell. The two platform implementations live in tunnel_shell_unix.go and
// tunnel_shell_windows.go respectively.
type shellSession interface {
	// Read returns output from the shell (merged stdout + stderr).
	Read([]byte) (int, error)

	// Write sends input to the shell's stdin.
	Write([]byte) (int, error)

	// Resize informs the underlying PTY / ConPTY of a new terminal size.
	// Ignored gracefully if the resize fails.
	Resize(cols, rows uint16) error

	// Close terminates the shell process and releases all OS resources.
	Close() error

	// PtyMode reports what kind of terminal backs this shell: "pty" (Unix),
	// "conpty" (Windows 10 1809+ / Server 2019+), or "pipe" (Windows without
	// ConPTY — degraded fallback, see tunnel_shell_pipe_windows.go). The
	// viewers use this to show the operator when they're in degraded mode.
	PtyMode() string
}
