package main

// tunnel_shell_integration.go — the shells of the remote terminals report
// their working directory at each prompt, so the Oblireach Desktop can send a
// file dropped on a terminal to the shell's folder. The agent sets it up when
// it starts the shell of a terminal (tunnel_shell_windows.go,
// tunnel_shell_unix.go), never in a user's files, and starts the plain shell
// exactly as before when anything in that setup fails:
//
//   - CMD: the PROMPT of that one process (its environment block) starts with
//     OSC 9;9;<folder> ST ("current directory", ConEmu / Windows Terminal),
//     followed by the PROMPT it would have had ($P$G by default).
//   - Windows PowerShell: -NoExit -Command wraps the prompt function in effect
//     once the profiles ran: the user's prompt runs first, unchanged (oh-my-posh,
//     starship keep their $?), and the same sequence is added in front of what
//     it returns, for a FileSystem location only. Not a file: the execution
//     policy does not apply; ConstrainedLanguage-safe; all in try/catch.
//   - bash (Linux, macOS): --rcfile <the agent's file> -i instead of --login.
//     That root-owned file (tunnel_shell_integration_unix.go writes it) reads
//     what a login shell reads, in the same order, then adds OSC 7
//     (file://host/path, percent-encoded) to PROMPT_COMMAND. (--rcfile only
//     replaces ~/.bashrc: a bash built with SYS_BASHRC, Debian's and
//     Ubuntu's, still reads /etc/bash.bashrc first, and their /etc/profile
//     reads it again: twice, where --login read it once. Documented, never
//     worked around by touching that system file.)
//
// A terminal that does not know these sequences ignores them (the web's shell
// panel: xterm.js).

import (
	"errors"
	"strings"
	"unicode/utf16"
)

// cmdPromptPrefix: OSC 9;9;<cmd's current folder> ST, in CMD's PROMPT codes
// ($e = ESC, $P = the current drive and path).
const cmdPromptPrefix = `$e]9;9;$P$e\`

// cmdPromptValue is the PROMPT CMD gets: the folder report, then the prompt
// it would have shown (the user's own PROMPT, or CMD's default $P$G). Given
// its own result, it returns it unchanged.
func cmdPromptValue(existing string) string {
	if strings.HasPrefix(existing, cmdPromptPrefix) {
		return existing
	}
	if existing == "" {
		existing = "$P$G"
	}
	return cmdPromptPrefix + existing
}

// envName is the name of an environment entry "NAME=value". Windows' hidden
// per-drive entries ("=C:=C:\dir") keep their leading "=" in the name.
func envName(e string) string {
	if e == "" {
		return ""
	}
	if i := strings.IndexByte(e[1:], '='); i >= 0 {
		return e[:i+1]
	}
	return e
}

// envValue returns the value of key in env (names compared without case, as
// Windows does), and whether it is there.
func envValue(env []string, key string) (string, bool) {
	for _, e := range env {
		if n := envName(e); strings.EqualFold(n, key) {
			return e[len(n)+1:], true
		}
	}
	return "", false
}

// envWith returns env with key set to val: its entry replaced where it was
// (names compared without case; a duplicate dropped), appended when absent.
// The other entries keep their order.
func envWith(env []string, key, val string) []string {
	out := make([]string, 0, len(env)+1)
	set := false
	for _, e := range env {
		if strings.EqualFold(envName(e), key) {
			if !set {
				out = append(out, key+"="+val)
				set = true
			}
			continue
		}
		out = append(out, e)
	}
	if !set {
		out = append(out, key+"="+val)
	}
	return out
}

// utf16EnvBlock is env as a CreateProcess environment block
// (CREATE_UNICODE_ENVIRONMENT): each "NAME=value" NUL-terminated, the block
// ending with one more NUL. An empty entry is left out (it would end the block
// early); an entry holding a NUL is refused.
func utf16EnvBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, e := range env {
		if e == "" {
			continue
		}
		if strings.IndexByte(e, 0) >= 0 {
			return nil, errors.New("environment entry holds a NUL")
		}
		b = append(b, utf16.Encode([]rune(e))...)
		b = append(b, 0)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	return append(b, 0), nil
}

// psIntegrationCommand is given to powershell.exe -NoExit -Command "...": it
// holds no double quote (it travels inside one on the command line) and does
// not end with a backslash. The wrapped prompt adds OSC 9;9;<folder> ST
// before the user's prompt text, for a FileSystem location whose path holds no
// control character (never a sequence cut short).
const psIntegrationCommand = `try { if (-not $global:__oblianceSI -and $function:prompt) { $global:__oblianceSI = 1; $global:__oblianceP = $function:prompt; ` +
	`function global:prompt { $r = & $global:__oblianceP; try { $l = $executionContext.SessionState.Path.CurrentLocation; $p = $l.ProviderPath; ` +
	`if ($l.Provider.Name -eq 'FileSystem' -and $p -notmatch '[\x00-\x1f\x7f-\x9f]') { $r = [char]27 + ']9;9;' + $p + [char]27 + '\' + $r } } catch {}; $r } } } catch {}`

// psCommandLine is the command line of an integrated Windows PowerShell.
func psCommandLine() string {
	return `powershell.exe -NoLogo -NoExit -Command "` + psIntegrationCommand + `"`
}

// bashIntegrationFile is the agent's bash rcfile, in its config folder.
const bashIntegrationFile = "shell-integration.bash"

// bashIntegration is that file (bash 3.2 and later: macOS's /bin/bash too).
//   - The login files, as bash --login reads them: /etc/profile, then the
//     first of ~/.bash_profile, ~/.bash_login, ~/.profile (~: $HOME, else the
//     account's home, like bash); ~/.bash_logout at exit (an EXIT trap set
//     first, so a user's own EXIT trap still wins).
//   - OSC 7 at each prompt, first in PROMPT_COMMAND (the user's own commands
//     run after it and see the same $?): file://<host><path>, every byte but
//     A-Z a-z 0-9 / . _ ~ - percent-encoded (never a control character in the
//     sequence). The encoding runs in a subshell with LC_ALL=C (bytes, not
//     characters; the shell's own locale is never touched).
//   - A read-only PROMPT_COMMAND is left alone (no error at start-up).
//   - Every variable that may be unset is read as ${name:-} (set -u in a
//     user's files breaks nothing).
const bashIntegration = `# Obliance agent: terminal shell integration (written by the agent; not a user file).
# The agent starts the shells of its remote terminals with: bash --rcfile <this file> -i
# It reads what a login shell reads, in the same order, then reports the shell's
# working directory at each prompt (OSC 7), which the Oblireach Desktop uses to send
# a file dropped on the terminal to that folder. No user file is changed.
# Rewritten by the agent when it differs: do not edit.
if [ -z "${__OBLIANCE_SI:-}" ]; then
__OBLIANCE_SI=1
trap '[ -r ~/.bash_logout ] && . ~/.bash_logout' EXIT
[ -r /etc/profile ] && . /etc/profile
if [ -r ~/.bash_profile ]; then . ~/.bash_profile
elif [ -r ~/.bash_login ]; then . ~/.bash_login
elif [ -r ~/.profile ]; then . ~/.profile
fi
__obliance_urlencode() {
  __obliance_s=${1:-}
  while [ -n "$__obliance_s" ]; do
    __obliance_k=${__obliance_s%%[!A-Za-z0-9/._~-]*}
    printf '%s' "$__obliance_k"
    __obliance_s=${__obliance_s#"$__obliance_k"}
    if [ -n "$__obliance_s" ]; then
      printf -v __obliance_n '%d' "'$__obliance_s"
      printf '%%%02X' $(( __obliance_n & 255 ))
      __obliance_s=${__obliance_s#?}
    fi
  done
}
__obliance_osc7_print() (
  LC_ALL=C
  printf '\033]7;file://'
  __obliance_urlencode "${HOSTNAME:-}"
  __obliance_urlencode "${PWD:-}"
  printf '\033\\'
)
__obliance_osc7() {
  local __obliance_rc=$?
  __obliance_osc7_print
  return $__obliance_rc
}
if ( PROMPT_COMMAND=__obliance_osc7 ) 2>/dev/null; then
  case "$(declare -p PROMPT_COMMAND 2>/dev/null)" in
    'declare -a'*) PROMPT_COMMAND=(__obliance_osc7 ${PROMPT_COMMAND[@]+"${PROMPT_COMMAND[@]}"}) ;;
    *) PROMPT_COMMAND="__obliance_osc7${PROMPT_COMMAND:+
${PROMPT_COMMAND:-}}" ;;
  esac
fi
fi
`
