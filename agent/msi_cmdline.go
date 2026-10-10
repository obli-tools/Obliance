package main

import (
	"errors"
	"os/exec"
	"strings"
)

// msiexec command line of a software compliance MSI source.
//
// The source's "install parameters" are written the way msiexec takes them,
// e.g.  SERVERURL="https://passly.example" APIKEY="abc"  (PowerShell-escaped
// quotes `" are accepted too, so a line copied from a PS script works). They
// are passed VERBATIM (raw Windows command line): msiexec parses its own
// command line, and Go's per-argument quoting would turn PROP="a b" into
// "PROP=\"a b\"", which msiexec rejects. /quiet and /norestart are added
// unless the parameters already choose a UI level / restart behaviour.

var errMsiBadPath = errors.New("msi: invalid package path")

// msiNormalizeParams: PowerShell `" → ", no line breaks / control chars.
func msiNormalizeParams(params string) string {
	params = strings.ReplaceAll(params, "`\"", "\"")
	params = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, params)
	return strings.Join(strings.Fields(params), " ")
}

// msiSwitchTokens returns the lower-cased switch tokens (/x or -x) outside
// quotes.
func msiSwitchTokens(params string) []string {
	var out []string
	inQ := false
	start := -1
	flush := func(end int) {
		if start >= 0 {
			tok := params[start:end]
			if strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "-") {
				out = append(out, strings.ToLower(tok))
			}
			start = -1
		}
	}
	for i := 0; i < len(params); i++ {
		c := params[i]
		switch {
		case c == '"':
			inQ = !inQ
			if start < 0 {
				start = i
			}
		case c == ' ' && !inQ:
			flush(i)
		default:
			if start < 0 {
				start = i
			}
		}
	}
	flush(len(params))
	return out
}

// msiCommandLine builds `msiexec.exe <action> "<target>" <params> [/quiet] [/norestart]`.
// action is "/i" or "/x"; target is a package path or a product code.
func msiCommandLine(action, target, params string) (string, error) {
	if target == "" || strings.ContainsAny(target, "\"\r\n") {
		return "", errMsiBadPath
	}
	params = msiNormalizeParams(params)
	hasUI, hasRestart := false, false
	for _, s := range msiSwitchTokens(params) {
		k := "/" + strings.TrimLeft(s, "/-")
		switch {
		case strings.HasPrefix(k, "/q"), k == "/passive":
			hasUI = true
		case k == "/norestart", k == "/forcerestart", k == "/promptrestart":
			hasRestart = true
		}
	}
	parts := []string{"msiexec.exe", action, `"` + target + `"`}
	if params != "" {
		parts = append(parts, params)
	}
	if !hasUI {
		parts = append(parts, "/quiet")
	}
	if !hasRestart {
		parts = append(parts, "/norestart")
	}
	return strings.Join(parts, " "), nil
}

// msiExitOK: 0, or success with a reboot required / initiated.
func msiExitOK(err error) bool {
	if err == nil {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case 3010, 1641:
			return true
		}
	}
	return false
}
