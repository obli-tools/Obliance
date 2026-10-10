//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Win32 lazy-loaded ConPTY functions ────────────────────────────────────────

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCreatePseudoConsole           = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole           = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole            = kernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttrList  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute     = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList = kernel32.NewProc("DeleteProcThreadAttributeList")
)

// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = ProcThreadAttributeValue(22, FALSE, TRUE, FALSE)
const procThreadAttributePseudoConsole uintptr = 0x00020016

// winCoord mirrors the Win32 COORD struct (2 × int16, packed as uint32).
type winCoord struct{ X, Y int16 }

func (c winCoord) pack() uintptr { return uintptr(*(*uint32)(unsafe.Pointer(&c))) }

// ── STARTUPINFOEXW (extends STARTUPINFOW with a proc-thread attribute list) ──

type startupInfoEx struct {
	windows.StartupInfo
	lpAttributeList uintptr // LPPROC_THREAD_ATTRIBUTE_LIST
}

// ── winShell ──────────────────────────────────────────────────────────────────

type winShell struct {
	hPC       windows.Handle
	writePipe *os.File // agent → ConPTY (shell stdin)
	readPipe  *os.File // ConPTY → agent (shell stdout/stderr)
	process   windows.Handle
	thread    windows.Handle
}

// newShellSession creates a Windows ConPTY and spawns a shell inside it.
// If wtsSessionId > 0, the shell runs in the specified WTS user session
// (using WTSQueryUserToken + CreateProcessAsUser). Otherwise it runs as SYSTEM.
// Requires Windows 10 Build 1809 (RS5) or later.
//
// `sessionToken` is part of the cross-platform signature (the Unix
// build wraps the shell in tmux for resume support); on Windows we
// don't have tmux so the parameter is currently unused — the comment
// stays so future maintainers know about the deliberate gap. A
// Windows resume implementation would need a ConPTY host process
// kept alive in a separate user service, which is materially more
// complex.
func newShellSession(cols, rows uint16, shellCmd string, _sessionToken string, wtsSessionId int) (shellSession, error) {
	// --- 0. ConPTY present? ---------------------------------------------------
	// LazyProc.Call PANICS when the export is missing (Windows Server 2016 /
	// Windows 10 before 1809): that crashed the whole agent. Check first and,
	// if missing, degrade to a plain pipe shell (tunnel_shell_pipe_windows.go)
	// instead of refusing outright — see tunnel_shell_conpty.go for what the
	// operator loses in that mode.
	if err := conptyAvailable(); err != nil {
		log.Printf("%s shell: ConPTY unavailable (%v): falling back to a plain pipe shell (degraded: no cursor addressing, no live resize, no full-screen TUI)", shellCmd, err)
		return newPipeShellSession(shellCmd, wtsSessionId)
	}

	// --- 1. Create two anonymous pipe pairs -----------------------------------
	var ptyInRead, ptyInWrite, ptyOutRead, ptyOutWrite windows.Handle
	if err := windows.CreatePipe(&ptyInRead, &ptyInWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("conpty: input pipe: %w", err)
	}
	if err := windows.CreatePipe(&ptyOutRead, &ptyOutWrite, nil, 0); err != nil {
		windows.CloseHandle(ptyInRead)
		windows.CloseHandle(ptyInWrite)
		return nil, fmt.Errorf("conpty: output pipe: %w", err)
	}

	// --- 2. CreatePseudoConsole -----------------------------------------------
	var hPC windows.Handle
	initSize := winCoord{X: int16(cols), Y: int16(rows)}
	hr, _, err := procCreatePseudoConsole.Call(
		initSize.pack(),
		uintptr(ptyInRead),
		uintptr(ptyOutWrite),
		0,
		uintptr(unsafe.Pointer(&hPC)),
	)
	if hr != 0 {
		windows.CloseHandle(ptyInRead)
		windows.CloseHandle(ptyInWrite)
		windows.CloseHandle(ptyOutRead)
		windows.CloseHandle(ptyOutWrite)
		return nil, fmt.Errorf("CreatePseudoConsole failed (HRESULT=0x%08x): %w", hr, err)
	}
	windows.CloseHandle(ptyInRead)
	windows.CloseHandle(ptyOutWrite)

	// --- 3. Build PROC_THREAD_ATTRIBUTE_LIST with ConPTY handle ---------------
	var attrListSize uintptr
	procInitializeProcThreadAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	if attrListSize == 0 {
		attrListSize = 64
	}
	attrList := make([]byte, attrListSize)
	r, _, err := procInitializeProcThreadAttrList.Call(
		uintptr(unsafe.Pointer(&attrList[0])),
		1, 0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r == 0 {
		procClosePseudoConsole.Call(uintptr(hPC))
		windows.CloseHandle(ptyInWrite)
		windows.CloseHandle(ptyOutRead)
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", err)
	}
	r, _, err = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&attrList[0])),
		0,
		procThreadAttributePseudoConsole,
		uintptr(hPC),
		unsafe.Sizeof(hPC),
		0, 0,
	)
	if r == 0 {
		procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
		procClosePseudoConsole.Call(uintptr(hPC))
		windows.CloseHandle(ptyInWrite)
		windows.CloseHandle(ptyOutRead)
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %w", err)
	}

	// --- 4. Build STARTUPINFOEXW and spawn shell ------------------------------
	siEx := startupInfoEx{}
	siEx.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.lpAttributeList = uintptr(unsafe.Pointer(&attrList[0]))

	var shellExe string
	switch shellCmd {
	case "cmd":
		shellExe = "cmd.exe /k"
	default:
		shellExe = "powershell.exe -NoLogo -NoExit"
	}
	cmdLine, err := syscall.UTF16PtrFromString(shellExe)
	if err != nil {
		procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
		procClosePseudoConsole.Call(uintptr(hPC))
		windows.CloseHandle(ptyInWrite)
		windows.CloseHandle(ptyOutRead)
		return nil, fmt.Errorf("conpty: cmdline: %w", err)
	}

	var procInfo windows.ProcessInformation
	createFlags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)

	// start launches the shell: as SYSTEM (default), or in the user's WTS
	// session. cmdPrompt: CMD's PROMPT reports its folder (its environment).
	start := func(line *uint16, cmdPrompt bool) error {
		if wtsSessionId > 0 {
			return createProcessInSession(uint32(wtsSessionId), line, createFlags, &siEx, &procInfo, cmdPrompt)
		}
		var env *uint16
		if cmdPrompt {
			env = systemPromptEnv()
		}
		return windows.CreateProcess(
			nil, line,
			nil, nil, false,
			createFlags,
			env, nil,
			(*windows.StartupInfo)(unsafe.Pointer(&siEx)),
			&procInfo,
		)
	}
	// The shell reports its folder at each prompt (tunnel_shell_integration.go:
	// OSC 9;9, the Oblireach Desktop sends a dropped file there): CMD through
	// its PROMPT, PowerShell through a wrapper of its prompt. Started plain, as
	// before, when that start fails.
	siLine, siPrompt := cmdLine, shellCmd == "cmd"
	if shellCmd != "cmd" {
		if l, e := syscall.UTF16PtrFromString(psCommandLine()); e == nil {
			siLine = l
		}
	}
	err = start(siLine, siPrompt)
	if err != nil && (siLine != cmdLine || siPrompt) {
		log.Printf("%s shell: the start with its folder report failed (%v): plain shell", shellCmd, err)
		procInfo = windows.ProcessInformation{}
		err = start(cmdLine, false)
	}
	procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
	if err != nil {
		procClosePseudoConsole.Call(uintptr(hPC))
		windows.CloseHandle(ptyInWrite)
		windows.CloseHandle(ptyOutRead)
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}

	return &winShell{
		hPC:       hPC,
		writePipe: os.NewFile(uintptr(ptyInWrite), "conpty-in"),
		readPipe:  os.NewFile(uintptr(ptyOutRead), "conpty-out"),
		process:   procInfo.Process,
		thread:    procInfo.Thread,
	}, nil
}

// conptyAvailable reports whether this Windows exposes the ConPTY API (the
// refusal names this Windows' build: tunnel_shell_conpty.go).
func conptyAvailable() error {
	for _, p := range []*windows.LazyProc{procCreatePseudoConsole, procResizePseudoConsole, procClosePseudoConsole} {
		if err := p.Find(); err != nil {
			var build uint32
			if v := windows.RtlGetVersion(); v != nil {
				build = v.BuildNumber
			}
			return conptyUnavailableError(build, p.Name)
		}
	}
	return nil
}

// promptEnvBlock is env with CMD's PROMPT reporting the folder
// (cmdPromptValue: the PROMPT env had, kept after it), as an environment
// block; nil when it cannot be built (the default environment then).
func promptEnvBlock(env []string) *uint16 {
	cur, _ := envValue(env, "PROMPT")
	b, err := utf16EnvBlock(envWith(env, "PROMPT", cmdPromptValue(cur)))
	if err != nil || len(b) == 0 {
		return nil
	}
	return &b[0]
}

// systemPromptEnv is the agent's own environment (what a SYSTEM shell
// inherits) with that PROMPT; nil: inherited as is.
func systemPromptEnv() *uint16 { return promptEnvBlock(os.Environ()) }

// createProcessInSession uses WTSQueryUserToken + CreateProcessAsUser to spawn
// a process in the interactive session of a logged-in user. cmdPrompt: the
// user's environment with CMD's PROMPT reporting the folder (the plain one
// when it cannot be built).
func createProcessInSession(sessionId uint32, cmdLine *uint16, createFlags uint32, siEx *startupInfoEx, procInfo *windows.ProcessInformation, cmdPrompt bool) error {
	var userToken windows.Handle
	r, _, err := procWTSQueryUserToken.Call(uintptr(sessionId), uintptr(unsafe.Pointer(&userToken)))
	if r == 0 {
		return fmt.Errorf("WTSQueryUserToken(session %d): %w", sessionId, err)
	}
	defer windows.CloseHandle(userToken)

	// Duplicate token as a primary token for CreateProcessAsUser
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		windows.Token(userToken),
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	// Create the user's environment block
	var envBlock uintptr
	r, _, err = procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&envBlock)),
		uintptr(primaryToken),
		0, // don't inherit parent env
	)
	if r == 0 {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer procDestroyEnvironmentBlock.Call(envBlock)
	var promptEnv *uint16 // (Go memory: referenced until the call returned)
	if cmdPrompt {
		if env, e := primaryToken.Environ(false); e == nil {
			promptEnv = promptEnvBlock(env)
		}
	}
	envArg := envBlock
	if promptEnv != nil {
		envArg = uintptr(unsafe.Pointer(promptEnv))
	}

	// Get user profile directory for lpCurrentDirectory
	var profileDir *uint16
	profileDir, _ = getUserProfileDir(primaryToken)

	// CreateProcessAsUserW
	r, _, err = procCreateProcessAsUserW.Call(
		uintptr(primaryToken),
		0, // lpApplicationName
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, // process/thread security attrs
		0, // bInheritHandles = FALSE
		uintptr(createFlags),
		envArg,
		uintptr(unsafe.Pointer(profileDir)),
		uintptr(unsafe.Pointer(&siEx.StartupInfo)),
		uintptr(unsafe.Pointer(procInfo)),
	)
	runtime.KeepAlive(promptEnv)
	if r == 0 {
		return fmt.Errorf("CreateProcessAsUserW: %w", err)
	}
	return nil
}

// getUserProfileDir returns the user profile directory for a token (e.g. C:\Users\john).
func getUserProfileDir(token windows.Token) (*uint16, error) {
	procGetUserProfileDirectoryW := userenv.NewProc("GetUserProfileDirectoryW")
	var size uint32 = 260
	buf := make([]uint16, size)
	r, _, err := procGetUserProfileDirectoryW.Call(
		uintptr(token),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return nil, err
	}
	return &buf[0], nil
}

func (s *winShell) PtyMode() string { return "conpty" }

func (s *winShell) Read(p []byte) (int, error)  { return s.readPipe.Read(p) }
func (s *winShell) Write(p []byte) (int, error) { return s.writePipe.Write(p) }

func (s *winShell) Resize(cols, rows uint16) error {
	coord := winCoord{X: int16(cols), Y: int16(rows)}
	hr, _, err := procResizePseudoConsole.Call(uintptr(s.hPC), coord.pack())
	if hr != 0 {
		return fmt.Errorf("ResizePseudoConsole (HRESULT=0x%08x): %w", hr, err)
	}
	return nil
}

func (s *winShell) Close() error {
	s.writePipe.Close()
	s.readPipe.Close()
	if s.process != 0 {
		windows.TerminateProcess(s.process, 1)
		windows.CloseHandle(s.process)
	}
	if s.thread != 0 {
		windows.CloseHandle(s.thread)
	}
	if s.hPC != 0 {
		procClosePseudoConsole.Call(uintptr(s.hPC))
	}
	return nil
}
