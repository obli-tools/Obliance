package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The refusal of a console on a Windows without ConPTY: complete (what is
// needed, from which version, this system's build, the missing function) and
// typed (the terminal's frame code conpty_unsupported), wrapped or not.
func TestConptyUnavailableError(t *testing.T) {
	err := conptyUnavailableError(9600, "CreatePseudoConsole")
	msg := err.Error()
	for _, want := range []string{"CMD / PowerShell", "ConPTY", "Windows 10 1809", "Windows Server 2019", "build 17763", "build 9600", "CreatePseudoConsole is missing"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	if !errors.Is(err, errConptyUnsupported) {
		t.Error("errors.Is(conpty error, errConptyUnsupported) = false")
	}
	wrapped := fmt.Errorf("open_remote_tunnel(cmd): start shell: %w", err)
	if got := shellTunnelErrorCode(wrapped); got != "conpty_unsupported" {
		t.Errorf("code of the wrapped refusal = %q, want conpty_unsupported", got)
	}
	if got := shellTunnelErrorCode(errors.New("conpty: input pipe: broken")); got != "agent_error" {
		t.Errorf("code of another failure = %q, want agent_error", got)
	}
	unknown := conptyUnavailableError(0, "").Error()
	if strings.Contains(unknown, "build 0") || strings.Contains(unknown, "missing") || !strings.Contains(unknown, "this Windows version") {
		t.Errorf("unknown build: %q", unknown)
	}
	if conptyMinBuild != 17763 {
		t.Errorf("conptyMinBuild = %d", conptyMinBuild)
	}
}
