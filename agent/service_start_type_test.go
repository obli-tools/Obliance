package main

import (
	"strings"
	"testing"
)

func TestNormalizeServiceStartType(t *testing.T) {
	ok := []struct{ goos, in, want string }{
		{"windows", "auto", "auto"},
		{"windows", " Auto ", "auto"},
		{"windows", "auto_delayed", "auto_delayed"},
		{"windows", "MANUAL", "manual"},
		{"windows", "disabled", "disabled"},
		{"linux", "auto", "auto"},
		{"linux", "manual", "manual"},
		{"linux", "disabled", "disabled"},
	}
	for _, c := range ok {
		got, err := normalizeServiceStartType(c.goos, c.in)
		if err != nil || got != c.want {
			t.Errorf("normalizeServiceStartType(%q, %q) = %q, %v; want %q", c.goos, c.in, got, err, c.want)
		}
	}
	bad := []struct{ goos, in string }{
		{"windows", ""},
		{"windows", "boot"},
		{"windows", "system"},
		{"windows", "automatic"},
		{"linux", "auto_delayed"},
		{"darwin", "auto_delayed"},
		{"linux", "static"},
	}
	for _, c := range bad {
		if got, err := normalizeServiceStartType(c.goos, c.in); err == nil {
			t.Errorf("normalizeServiceStartType(%q, %q) = %q, want an error", c.goos, c.in, got)
		}
	}
}

func TestValidateServiceName(t *testing.T) {
	ok := []struct{ goos, name string }{
		{"windows", "Spooler"},
		{"windows", "MSSQL$SQLEXPRESS"},
		{"windows", "Some Service With Spaces"},
		{"windows", "CDPUserSvc_4a5b6"},
		{"linux", "ssh.service"},
		{"linux", "getty@tty1.service"},
		{"linux", `systemd-fsck@dev-disk-by\x2duuid-1234.service`},
		{"linux", "nginx"},
	}
	for _, c := range ok {
		if err := validateServiceName(c.goos, c.name); err != nil {
			t.Errorf("validateServiceName(%q, %q) = %v, want nil", c.goos, c.name, err)
		}
	}
	bad := []struct{ goos, name string }{
		{"windows", ""},
		{"windows", "a/b"},
		{"windows", `a\b`},
		{"windows", "line\nbreak"},
		{"windows", "nul\x00"},
		{"windows", " Spooler"},
		{"windows", strings.Repeat("a", maxServiceNameLen+1)},
		{"linux", "--now"},
		{"linux", "-ssh"},
		{"linux", "ssh service"},
		{"linux", "ssh;reboot"},
		{"linux", "../../etc/passwd"},
		{"linux", "sshé.service"},
		{"linux", "tab\t.service"},
	}
	for _, c := range bad {
		if err := validateServiceName(c.goos, c.name); err == nil {
			t.Errorf("validateServiceName(%q, %q) = nil, want an error", c.goos, c.name)
		}
	}
}

func TestIsProtectedService(t *testing.T) {
	protected := []struct{ goos, name string }{
		{"windows", "OblianceAgent"},
		{"windows", "oblianceagent"},
		{"windows", "OblireachAgent"},
		{"windows", "ObliReachAgent"},
		{"windows", " OBLIANCEAGENT "},
		{"linux", "obliance-agent"},
		{"linux", "obliance-agent.service"},
		{"linux", "obliance-watchdog.service"},
		{"linux", "obliance-watchdog.timer"},
		{"linux", "oblireach-agent.service"},
		{"linux", "Obliance-Agent.service"},
	}
	for _, c := range protected {
		if !isProtectedService(c.goos, c.name) {
			t.Errorf("isProtectedService(%q, %q) = false, want true", c.goos, c.name)
		}
	}
	free := []struct{ goos, name string }{
		{"windows", "Spooler"},
		{"windows", "OblianceAgent2"},
		{"windows", "obliance-agent"},
		{"linux", "ssh.service"},
		{"linux", "OblianceAgent"},
		{"linux", "obliance-agent-helper.service"},
	}
	for _, c := range free {
		if isProtectedService(c.goos, c.name) {
			t.Errorf("isProtectedService(%q, %q) = true, want false", c.goos, c.name)
		}
	}
}

func TestSystemdStartTypeName(t *testing.T) {
	cases := map[string]string{
		"enabled":         "auto",
		"enabled-runtime": "auto",
		"disabled":        "manual",
		"masked":          "disabled",
		"masked-runtime":  "disabled",
		"static":          "static",
		"indirect":        "indirect",
		"":                "",
	}
	for in, want := range cases {
		if got := systemdStartTypeName(in); got != want {
			t.Errorf("systemdStartTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSystemdStepsAndReached(t *testing.T) {
	verbs := func(st string) string {
		var v []string
		for _, s := range systemdSteps(st) {
			v = append(v, s.verb)
		}
		return strings.Join(v, ",")
	}
	if got := verbs("auto"); got != "unmask,enable" {
		t.Errorf("auto steps = %s", got)
	}
	if got := verbs("manual"); got != "unmask,disable" {
		t.Errorf("manual steps = %s", got)
	}
	if got := verbs("disabled"); got != "disable,mask" {
		t.Errorf("disabled steps = %s", got)
	}
	if systemdSteps("auto_delayed") != nil {
		t.Errorf("auto_delayed must have no systemd steps")
	}
	reached := []struct {
		st, state string
		want      bool
	}{
		{"auto", "enabled", true},
		{"auto", "static", false},
		{"manual", "disabled", true},
		{"manual", "static", true},
		{"manual", "enabled", false},
		{"manual", "masked", false},
		{"disabled", "masked", true},
		{"disabled", "disabled", false},
	}
	for _, c := range reached {
		if got := systemdReached(c.st, c.state); got != c.want {
			t.Errorf("systemdReached(%q, %q) = %v, want %v", c.st, c.state, got, c.want)
		}
	}
}
