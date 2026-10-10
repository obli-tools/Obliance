package main

import (
	"strings"
	"testing"
)

func TestObliReachWindowsArtifactByOS(t *testing.T) {
	cases := []struct {
		arch  string
		major uint32
		want  string
	}{
		{"amd64", 10, "oblireach-agent.msi"},
		{"amd64", 0, "oblireach-agent.msi"}, // version unknown: modern (as before)
		{"amd64", 6, obliReachArtifactNT6},  // 7 / 8.1 / 2008 R2 / 2012 / 2012 R2
		{"386", 6, ""},
		{"386", 10, ""},
		{"arm64", 10, ""},
	}
	for _, c := range cases {
		if got := obliReachWindowsArtifact(c.arch, c.major); got != c.want {
			t.Errorf("%s/%d: %q want %q", c.arch, c.major, got, c.want)
		}
	}
}

func TestObliReachNT6Mismatch(t *testing.T) {
	// Not an nt6 machine: never rejected here (bad_manifest logic unchanged).
	if msg := obliReachNT6Mismatch("oblireach-agent.msi", "", 10, 0, 19045); msg != "" {
		t.Fatalf("modern OS rejected: %q", msg)
	}
	// nt6 machine, server without an nt6 build: "" or the modern MSI.
	for _, file := range []string{"", "oblireach-agent.msi"} {
		msg := obliReachNT6Mismatch(obliReachArtifactNT6, file, 6, 3, 9600)
		if !strings.HasPrefix(msg, "os_too_old:") || !strings.Contains(msg, "6.3 build 9600") {
			t.Fatalf("file %q: %q", file, msg)
		}
	}
	// The right file, or garbage (still bad_manifest), is not this case.
	if msg := obliReachNT6Mismatch(obliReachArtifactNT6, obliReachArtifactNT6, 6, 1, 7601); msg != "" {
		t.Fatalf("own file rejected: %q", msg)
	}
	if msg := obliReachNT6Mismatch(obliReachArtifactNT6, "../evil.msi", 6, 1, 7601); msg != "" {
		t.Fatalf("garbage must stay bad_manifest: %q", msg)
	}
}

// nt6ReachOps is a fake Windows NT 6.x platform: artifact = the nt6 MSI and
// RejectFile as implemented by the real Windows ops.
type nt6ReachOps struct {
	*fakeReachOps
}

func (n *nt6ReachOps) RejectFile(ours, file string) string {
	return obliReachNT6Mismatch(ours, file, 6, 1, 7601)
}

func TestObliReachNT6ManifestStates(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		state   string
		errCode string
		install bool
	}{
		{"server without nt6 build sends the modern MSI", "oblireach-agent.msi", orStateUnsupported, "os_too_old", false},
		{"server without any build", "", orStateUnsupported, "os_too_old", false},
		{"garbage stays bad_manifest", "oblireach-agent.exe", orStateFailed, "bad_manifest", false},
		{"server ships the nt6 build", obliReachArtifactNT6, orStateUpToDate, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newReachHarness(t, true)
			h.ops.artifact = obliReachArtifactNT6
			h.m = newObliReachManager(&nt6ReachOps{h.ops}, h.env, h.statePath)
			d := h.desired()
			d.File = c.file
			h.m.SetDesired(d)
			h.afterSpread()
			r := h.run()
			if r.State != c.state || !strings.HasPrefix(r.Error, c.errCode) {
				t.Fatalf("state=%q error=%q, want %q %q", r.State, r.Error, c.state, c.errCode)
			}
			if got := len(h.ops.installs) > 0; got != c.install {
				t.Fatalf("installs=%d, want install=%v", len(h.ops.installs), c.install)
			}
		})
	}
}
