// Package launchd holds the pure (OS-independent) helpers used to drive the
// macOS launchd jobs of the agent and its menu-bar tray: parsing of
// `launchctl print` / `ps` output and generation of the job plists.
//
// No build tag and stdlib only: the package must stay compilable everywhere
// (Go 1.20 nt6 Windows line included) so its unit tests run on any host.
package launchd

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// AgentLabel is the label of the root LaunchDaemon.
	AgentLabel = "com.obliance.agent"
	// AgentTarget is the only launchd target used for the daemon. The legacy
	// load/unload/disable subcommands are never used for it.
	AgentTarget = "system/" + AgentLabel
	// TrayLabel is the label of the per-user LaunchAgent (menu-bar icon).
	TrayLabel = "com.obliance.tray"
)

// topLevelValue returns the value of "key = value" found at the first
// nesting level of `launchctl print` output (one tab, or a few spaces, of
// indentation). Nested sections ("endpoints", "event triggers", ...) also
// contain "state = ..." lines, they must not be mistaken for the job state.
func topLevelValue(out, key string) (string, bool) {
	prefix := key + " = "
	var fallback string
	found := false
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		indent := line[:len(line)-len(trimmed)]
		value := strings.TrimSpace(trimmed[len(prefix):])
		if indent == "\t" || (len(indent) > 0 && len(indent) <= 4 && strings.Trim(indent, " ") == "") {
			return value, true
		}
		if !found {
			fallback, found = value, true
		}
	}
	return fallback, found
}

// ServiceState returns the job state reported by `launchctl print <target>`
// ("running", "not running", "waiting", ...), or "" when absent.
func ServiceState(printOutput string) string {
	v, _ := topLevelValue(printOutput, "state")
	return v
}

// IsRunning reports whether `launchctl print <target>` output describes a
// running job.
func IsRunning(printOutput string) bool {
	return ServiceState(printOutput) == "running"
}

// PID returns the top-level "pid = N" of `launchctl print` output, 0 if none.
func PID(printOutput string) int {
	v, ok := topLevelValue(printOutput, "pid")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// GUISessionUIDs parses `ps -axo uid=,comm=` output and returns the sorted,
// de-duplicated UIDs owning a loginwindow process, i.e. the users that have
// an Aqua (GUI) session, foreground or behind fast user switching. UID 0
// (loginwindow at the login screen) is skipped.
func GUISessionUIDs(psOutput string) []int {
	seen := map[int]bool{}
	var uids []int
	for _, line := range strings.Split(psOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil || uid <= 0 {
			continue
		}
		comm := strings.Join(fields[1:], " ")
		if filepath.Base(strings.ReplaceAll(comm, "\\", "/")) != "loginwindow" {
			continue
		}
		if !seen[uid] {
			seen[uid] = true
			uids = append(uids, uid)
		}
	}
	sort.Ints(uids)
	return uids
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

const plistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
`

// DaemonPlist returns the LaunchDaemon plist of the agent.
func DaemonPlist(label, program, logFile string) string {
	return plistHeader + fmt.Sprintf(`<dict>
    <key>Label</key>
    <string>%s</string>

    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>

    <!-- Restart automatically if it crashes -->
    <key>KeepAlive</key>
    <true/>

    <!-- Start on boot -->
    <key>RunAtLoad</key>
    <true/>

    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>

    <!-- Lower priority so it doesn't interfere with the user's work -->
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
`, xmlEscape(label), xmlEscape(program), xmlEscape(logFile), xmlEscape(logFile))
}

// TrayAgentPlist returns the per-user LaunchAgent plist of the menu-bar tray.
//
//   - LimitLoadToSessionType=Aqua: one instance per GUI login session,
//     started by launchd for every user that logs in.
//   - KeepAlive/SuccessfulExit=false: relaunched after a crash, but "Quit"
//     (clean exit 0) is honoured until the next login.
//   - No StandardOutPath: a shared file in /tmp would belong to the first
//     user and be unwritable for the others; the tray logs to
//     ~/Library/Logs/Obliance/tray.log itself.
func TrayAgentPlist(label, program string) string {
	return plistHeader + fmt.Sprintf(`<dict>
    <key>Label</key>
    <string>%s</string>

    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
`, xmlEscape(label), xmlEscape(program))
}
