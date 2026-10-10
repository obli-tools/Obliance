package launchd

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"
)

const printRunning = "system/com.obliance.agent = {\n" +
	"\tactive count = 1\n" +
	"\tpath = /Library/LaunchDaemons/com.obliance.agent.plist\n" +
	"\ttype = LaunchDaemon\n" +
	"\tstate = running\n" +
	"\n" +
	"\tprogram = /usr/local/bin/obliance-agent\n" +
	"\targuments = {\n" +
	"\t\t/usr/local/bin/obliance-agent\n" +
	"\t}\n" +
	"\n" +
	"\tpid = 4242\n" +
	"\tendpoints = {\n" +
	"\t\t\"x\" = {\n" +
	"\t\t\tstate = not running\n" +
	"\t\t}\n" +
	"\t}\n" +
	"}\n"

const printStopped = "system/com.obliance.agent = {\n" +
	"\tactive count = 0\n" +
	"\tpath = /Library/LaunchDaemons/com.obliance.agent.plist\n" +
	"\ttype = LaunchDaemon\n" +
	"\tstate = not running\n" +
	"\n" +
	"\tevent triggers = {\n" +
	"\t\tstate = running\n" +
	"\t}\n" +
	"\tlast exit code = 78: EX_CONFIG\n" +
	"}\n"

func TestServiceState(t *testing.T) {
	cases := []struct {
		name, out, state string
		running          bool
		pid              int
	}{
		{"running", printRunning, "running", true, 4242},
		{"stopped ignores nested state", printStopped, "not running", false, 0},
		{"not found", "Could not find service \"com.obliance.agent\" in domain for system", "", false, 0},
		{"empty", "", "", false, 0},
		{"spaces indentation", "x = {\n    state = running\n    pid = 7\n}\n", "running", true, 7},
		{"nested only falls back", "x = {\n\t\tstate = waiting\n}\n", "waiting", false, 0},
		{"crlf", "x = {\r\n\tstate = running\r\n}\r\n", "running", true, 0},
	}
	for _, c := range cases {
		if got := ServiceState(c.out); got != c.state {
			t.Errorf("%s: ServiceState = %q, want %q", c.name, got, c.state)
		}
		if got := IsRunning(c.out); got != c.running {
			t.Errorf("%s: IsRunning = %v, want %v", c.name, got, c.running)
		}
		if got := PID(c.out); got != c.pid {
			t.Errorf("%s: PID = %d, want %d", c.name, got, c.pid)
		}
	}
}

func TestGUISessionUIDs(t *testing.T) {
	ps := "    0 /sbin/launchd\n" +
		"    0 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\n" +
		"  501 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\n" +
		"  502 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\n" +
		"  501 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\n" +
		"  503 /Applications/Not loginwindow.app/Contents/MacOS/helper\n" +
		"  504 /usr/bin/loginwindowx\n" +
		"  abc loginwindow\n" +
		"  505 loginwindow\n" +
		"\n"
	got := GUISessionUIDs(ps)
	want := []int{501, 502, 505}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GUISessionUIDs = %v, want %v", got, want)
	}
	if got := GUISessionUIDs(""); len(got) != 0 {
		t.Fatalf("empty ps: %v", got)
	}
}

// checkWellFormed fails the test when s is not well-formed XML.
func checkWellFormed(t *testing.T, s string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(s))
	d.Strict = true
	d.Entity = xml.HTMLEntity
	for {
		_, err := d.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return
			}
			t.Fatalf("plist not well-formed: %v\n%s", err, s)
		}
	}
}

func TestDaemonPlist(t *testing.T) {
	p := DaemonPlist(AgentLabel, "/usr/local/bin/obliance-agent", "/var/log/obliance-agent.log")
	checkWellFormed(t, p)
	for _, want := range []string{
		"<string>com.obliance.agent</string>",
		"<string>/usr/local/bin/obliance-agent</string>",
		"<key>KeepAlive</key>\n    <true/>",
		"<key>RunAtLoad</key>\n    <true/>",
		"<string>/var/log/obliance-agent.log</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("daemon plist missing %q", want)
		}
	}
	if strings.Contains(p, "Disabled") {
		t.Errorf("daemon plist must never carry a Disabled key")
	}
}

func TestTrayAgentPlist(t *testing.T) {
	p := TrayAgentPlist(TrayLabel, "/usr/local/bin/obliance-tray")
	checkWellFormed(t, p)
	for _, want := range []string{
		"<string>com.obliance.tray</string>",
		"<string>/usr/local/bin/obliance-tray</string>",
		"<key>LimitLoadToSessionType</key>\n    <string>Aqua</string>",
		"<key>SuccessfulExit</key>\n        <false/>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("tray plist missing %q", want)
		}
	}
	if strings.Contains(p, "/tmp/") {
		t.Errorf("tray plist must not log to a shared /tmp file")
	}
	// Escaping of odd program paths.
	p = TrayAgentPlist(TrayLabel, "/opt/a&b<c>")
	checkWellFormed(t, p)
	if !strings.Contains(p, "/opt/a&amp;b&lt;c&gt;") {
		t.Errorf("program path not escaped:\n%s", p)
	}
}

func TestTargets(t *testing.T) {
	if AgentTarget != "system/com.obliance.agent" {
		t.Fatalf("AgentTarget = %q", AgentTarget)
	}
}
