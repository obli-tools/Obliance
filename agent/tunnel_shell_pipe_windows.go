//go:build windows

package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// winPipeShell is the degraded fallback used when this Windows has no ConPTY
// (Windows Server 2012 R2 / 2016, Windows 10 before build 1809 — see
// tunnel_shell_conpty.go): cmd.exe / powershell.exe wired to plain anonymous
// pipes instead of a pseudo console.
//
// Known limitations, accepted so the console stays usable rather than
// unavailable on these old builds:
//   - No cursor addressing: the shell believes it talks to a dumb pipe, so it
//     never uses ANSI/VT sequences for things like tab-completion redraw or
//     colors. Output is whatever the shell writes to stdout/stderr, merged,
//     in order.
//   - No live resize: Resize is a no-op (a plain pipe carries no notion of
//     terminal geometry, so tools that query the console size — e.g.
//     PowerShell's $Host.UI.RawUI.WindowSize — see a default/undefined size).
//   - No full-screen interactive TUI (there is no console buffer to draw
//     into): tools like `vim`/`less`/the interactive `powershell_ise` prompt
//     helpers won't render correctly. Plain line-oriented commands work fine.
//   - `cls`/`Clear-Host` do not clear anything server-side — the client may
//     choose to clear its own local scrollback when it sees the command echoed,
//     but nothing is done here at the protocol level.
//   - The working-directory OSC reporting used elsewhere (tunnel_shell_integration.go)
//     is ConPTY/PTY-oriented and not wired into this fallback: Oblireach
//     Desktop's "drop file into shell's folder" always falls back to asking
//     for the folder in this mode.
type winPipeShell struct {
	writePipe *os.File // agent -> shell stdin
	readPipe  *os.File // shell stdout+stderr (merged) -> agent
	process   windows.Handle
	thread    windows.Handle
	closeOnce sync.Once
}

// newPipeShellSession spawns cmd.exe/powershell.exe with its stdio redirected
// to plain anonymous pipes (no pseudo console). If wtsSessionId > 0 it runs in
// that WTS user session (WTSQueryUserToken + CreateProcessAsUser, mirroring
// the ConPTY path in tunnel_shell_windows.go but without the ConPTY
// proc-thread attribute list); otherwise it runs as SYSTEM.
func newPipeShellSession(shellCmd string, wtsSessionId int) (shellSession, error) {
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(*sa))

	var stdinRead, stdinWrite, stdoutRead, stdoutWrite windows.Handle
	if err := windows.CreatePipe(&stdinRead, &stdinWrite, sa, 0); err != nil {
		return nil, fmt.Errorf("pipe shell: stdin pipe: %w", err)
	}
	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, sa, 0); err != nil {
		windows.CloseHandle(stdinRead)
		windows.CloseHandle(stdinWrite)
		return nil, fmt.Errorf("pipe shell: stdout pipe: %w", err)
	}
	// Both ends of a pipe made with an inheritable SECURITY_ATTRIBUTES are
	// inheritable; un-inherit the ends the agent itself keeps so they don't
	// leak into unrelated child processes started later.
	_ = windows.SetHandleInformation(stdinWrite, windows.HANDLE_FLAG_INHERIT, 0)
	_ = windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0)

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput = stdinRead
	si.StdOutput = stdoutWrite
	si.StdErr = stdoutWrite

	var shellExe string
	switch shellCmd {
	case "cmd":
		shellExe = "cmd.exe /k"
	default:
		shellExe = "powershell.exe -NoLogo -NoExit"
	}
	cmdLine, err := syscall.UTF16PtrFromString(shellExe)
	if err != nil {
		closeHandles(stdinRead, stdinWrite, stdoutRead, stdoutWrite)
		return nil, fmt.Errorf("pipe shell: cmdline: %w", err)
	}

	var procInfo windows.ProcessInformation
	createFlags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)

	if wtsSessionId > 0 {
		err = createProcessInSessionPipe(uint32(wtsSessionId), cmdLine, createFlags, &si, &procInfo)
	} else {
		err = windows.CreateProcess(nil, cmdLine, nil, nil, true, createFlags, nil, nil, &si, &procInfo)
	}
	// Whatever the outcome, the agent's copies of the CHILD's ends must go —
	// the child (on success) has its own duplicated handles by now.
	windows.CloseHandle(stdinRead)
	windows.CloseHandle(stdoutWrite)
	if err != nil {
		windows.CloseHandle(stdinWrite)
		windows.CloseHandle(stdoutRead)
		return nil, fmt.Errorf("pipe shell: CreateProcess: %w", err)
	}

	return &winPipeShell{
		writePipe: os.NewFile(uintptr(stdinWrite), "pipeshell-in"),
		readPipe:  os.NewFile(uintptr(stdoutRead), "pipeshell-out"),
		process:   procInfo.Process,
		thread:    procInfo.Thread,
	}, nil
}

// createProcessInSessionPipe is createProcessInSession's (tunnel_shell_windows.go)
// counterpart for the pipe fallback: plain STARTUPINFOW with redirected std
// handles instead of a ConPTY proc-thread attribute list, and
// bInheritHandles=TRUE so the duplicated pipe ends actually reach the child.
// No PROMPT/working-directory-reporting env customization here (documented
// limitation — see winPipeShell's doc comment).
func createProcessInSessionPipe(sessionId uint32, cmdLine *uint16, createFlags uint32, si *windows.StartupInfo, procInfo *windows.ProcessInformation) error {
	var userToken windows.Handle
	r, _, err := procWTSQueryUserToken.Call(uintptr(sessionId), uintptr(unsafe.Pointer(&userToken)))
	if r == 0 {
		return fmt.Errorf("WTSQueryUserToken(session %d): %w", sessionId, err)
	}
	defer windows.CloseHandle(userToken)

	var primaryToken windows.Token
	if err := windows.DuplicateTokenEx(
		windows.Token(userToken),
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	var envBlock uintptr
	r, _, err = procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&envBlock)),
		uintptr(primaryToken),
		0,
	)
	if r == 0 {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer procDestroyEnvironmentBlock.Call(envBlock)

	profileDir, _ := getUserProfileDir(primaryToken)

	r, _, err = procCreateProcessAsUserW.Call(
		uintptr(primaryToken),
		0, // lpApplicationName
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, // process/thread security attrs
		1, // bInheritHandles = TRUE — the redirected pipe ends must cross into the child
		uintptr(createFlags),
		envBlock,
		uintptr(unsafe.Pointer(profileDir)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(procInfo)),
	)
	if r == 0 {
		return fmt.Errorf("CreateProcessAsUserW: %w", err)
	}
	return nil
}

func closeHandles(hs ...windows.Handle) {
	for _, h := range hs {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}
}

func (s *winPipeShell) PtyMode() string { return "pipe" }

func (s *winPipeShell) Read(p []byte) (int, error)  { return s.readPipe.Read(p) }
func (s *winPipeShell) Write(p []byte) (int, error) { return s.writePipe.Write(p) }

// Resize is a no-op: a plain pipe carries no notion of terminal geometry.
func (s *winPipeShell) Resize(cols, rows uint16) error { return nil }

func (s *winPipeShell) Close() error {
	s.closeOnce.Do(func() {
		s.writePipe.Close()
		s.readPipe.Close()
		if s.process != 0 {
			windows.TerminateProcess(s.process, 1)
			windows.CloseHandle(s.process)
		}
		if s.thread != 0 {
			windows.CloseHandle(s.thread)
		}
	})
	return nil
}
