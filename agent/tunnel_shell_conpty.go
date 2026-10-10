package main

import (
	"errors"
	"fmt"
)

// The remote consoles on Windows (CMD, PowerShell) run in a pseudo console
// (ConPTY): Windows 10 1809 / Windows Server 2019, build 17763, or later.
// Windows Server 2012 R2 (9600) and 2016 (14393) do not have it. The
// server and the clients grey these consoles out when they know the build
// (POST /api/remote/sessions answers 409 conpty_unsupported); this text is
// what the operator reads when the agent is asked anyway.
const conptyMinBuild = 17763

// errConptyUnsupported marks a shell that cannot start because this Windows
// has no ConPTY (errors.Is): the terminal then says so with its own code.
var errConptyUnsupported = errors.New("conpty unsupported")

type conptyError struct{ text string }

func (e *conptyError) Error() string        { return e.text }
func (e *conptyError) Is(target error) bool { return target == errConptyUnsupported }

// conptyUnavailableError: the refusal, complete and explicit. build: this
// Windows' build number (0: unknown); missing: the ConPTY function not found.
func conptyUnavailableError(build uint32, missing string) error {
	system := "this Windows version"
	if build > 0 {
		system = fmt.Sprintf("this Windows (build %d)", build)
	}
	text := fmt.Sprintf("the remote console (CMD / PowerShell) needs the Windows pseudo console (ConPTY), "+
		"available from Windows 10 1809 / Windows Server 2019 (build %d) or later: %s does not have it", conptyMinBuild, system)
	if missing != "" {
		text += " (" + missing + " is missing)"
	}
	return &conptyError{text: text}
}

// shellTunnelErrorCode: the code of the terminal's error frame for a shell
// that could not start (the viewers translate conpty_unsupported).
func shellTunnelErrorCode(err error) string {
	if errors.Is(err, errConptyUnsupported) {
		return "conpty_unsupported"
	}
	return "agent_error"
}
