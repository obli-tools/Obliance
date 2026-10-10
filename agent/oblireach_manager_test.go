package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Fake OS actions ─────────────────────────────────────────────────────────

type fakeInstall struct {
	uninstallFirst bool
	version        string
	sha            string
}

type fakeReachOps struct {
	traits     obliReachTraits
	artifact   string
	precond    string
	probe      obliReachProbe
	busy       string
	sigErr     error
	installErr error
	startErr   error
	onVerify   func()
	onInstall  func()
	stageDir   string

	installs  []fakeInstall
	starts    int
	stops     int
	enforces  int
	discarded []string
}

func (f *fakeReachOps) Traits() obliReachTraits                 { return f.traits }
func (f *fakeReachOps) ArtifactName() string                    { return f.artifact }
func (f *fakeReachOps) Precondition(bool) string                { return f.precond }
func (f *fakeReachOps) Busy(obliReachProbe) string              { return f.busy }
func (f *fakeReachOps) DiscardStaging(dir string)               { f.discarded = append(f.discarded, dir) }
func (f *fakeReachOps) FinishStage(s obliReachStage, keep bool) { _ = os.Remove(s.Path) }

func (f *fakeReachOps) Probe(*ObliReachDesired, bool) obliReachProbe { return f.probe }

func (f *fakeReachOps) Stage(file string) (obliReachStage, error) {
	return obliReachStage{Dir: f.stageDir, Path: filepath.Join(f.stageDir, randomHex(4)+"-"+file)}, nil
}

func (f *fakeReachOps) VerifySignature(string) error {
	if f.onVerify != nil {
		f.onVerify()
	}
	return f.sigErr
}

func (f *fakeReachOps) Install(path string, want *ObliReachDesired, p obliReachProbe, uninstallFirst bool, srv obliReachServer) error {
	if _, err := os.Stat(path); err != nil {
		return errors.New("staged file missing")
	}
	f.installs = append(f.installs, fakeInstall{uninstallFirst: uninstallFirst, version: want.Version, sha: want.SHA256})
	if f.onInstall != nil {
		f.onInstall()
	}
	if f.installErr != nil {
		return f.installErr
	}
	f.probe = obliReachProbe{
		Installed: true, ServiceExists: true, ProductCode: "{NEW}",
		Version: want.Version, Hash: want.SHA256,
		Running: !f.traits.startAfterInstall, // the MSI starts the service itself
	}
	return nil
}

func (f *fakeReachOps) Start(obliReachServer) error {
	f.starts++
	if f.startErr != nil {
		return f.startErr
	}
	f.probe.Running = true
	return nil
}

func (f *fakeReachOps) Stop() {
	f.stops++
	f.probe.Running = false
	f.probe.StartDisabled = true
}

func (f *fakeReachOps) EnforceStopped(bool) bool {
	f.enforces++
	if f.probe.ServiceExists && (f.probe.Running || !f.probe.StartDisabled) {
		f.probe.Running = false
		f.probe.StartDisabled = true
		return true
	}
	return false
}

// ── Harness ─────────────────────────────────────────────────────────────────

var (
	winTraits  = obliReachTraits{alignByHash: false, selfUpdates: true, startAfterInstall: false, notRunningGrace: 5 * time.Minute}
	unixTraits = obliReachTraits{alignByHash: true, selfUpdates: false, startAfterInstall: true, notRunningGrace: 45 * time.Second}
)

type reachHarness struct {
	t         *testing.T
	m         *obliReachManager
	ops       *fakeReachOps
	now       time.Time
	privacy   bool
	agentBusy bool
	srv       *httptest.Server
	hits      int32
	payload   []byte
	sha       string
	noHeader  bool
	notifies  int
	statePath string
	env       obliReachEnv
}

func newReachHarness(t *testing.T, windowsLike bool) *reachHarness {
	t.Helper()
	h := &reachHarness{t: t, now: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}
	h.payload = []byte("fake ObliReach artifact 1.0.198 — not a real installer")
	sum := sha256.Sum256(h.payload)
	h.sha = hex.EncodeToString(sum[:])
	h.ops = &fakeReachOps{stageDir: t.TempDir()}
	if windowsLike {
		h.ops.traits, h.ops.artifact = winTraits, "oblireach-agent.msi"
	} else {
		h.ops.traits, h.ops.artifact = unixTraits, "oblireach-agent-linux-amd64"
	}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&h.hits, 1)
		if r.URL.Path != "/api/agent/download/"+h.ops.artifact || r.Header.Get("X-Api-Key") != "test-key" {
			http.NotFound(w, r)
			return
		}
		if !h.noHeader {
			w.Header().Set("X-Content-SHA256", h.sha)
		}
		_, _ = w.Write(h.payload)
	}))
	t.Cleanup(h.srv.Close)
	h.statePath = filepath.Join(t.TempDir(), "oblireach-manager.json")
	h.env = obliReachEnv{
		now:        func() time.Time { return h.now },
		privacy:    func() bool { return h.privacy },
		agentBusy:  func() bool { return h.agentBusy },
		server:     func() obliReachServer { return obliReachServer{URL: h.srv.URL, APIKey: "test-key"} },
		deviceUUID: func() string { return "4c4c4544-0042-3510-8052-b4c04f4e3732" },
		notify:     func() { h.notifies++ },
		jitter:     func() float64 { return 0 },
		client:     defaultObliReachEnv().client, // the real redirect policy
	}
	h.m = newObliReachManager(h.ops, h.env, h.statePath)
	return h
}

func (h *reachHarness) desired() *ObliReachDesired {
	return &ObliReachDesired{Enabled: true, Version: "1.0.198", File: h.ops.artifact, SHA256: h.sha, Size: int64(len(h.payload))}
}

func (h *reachHarness) alignedProbe(version string, running bool) obliReachProbe {
	return obliReachProbe{Installed: true, ServiceExists: true, ProductCode: "{OLD}", Version: version, Hash: h.sha, Running: running}
}

func (h *reachHarness) advance(d time.Duration) { h.now = h.now.Add(d) }

func (h *reachHarness) downloads() int { return int(atomic.LoadInt32(&h.hits)) }

func (h *reachHarness) run() *ObliReachReport {
	h.t.Helper()
	h.m.Reconcile()
	r := h.m.Report()
	if r == nil {
		h.t.Fatalf("no report after reconcile")
	}
	return r
}

func (h *reachHarness) afterSpread() { h.advance(orMissingSpread*time.Second + time.Second) }

func expectState(t *testing.T, r *ObliReachReport, state, reason string) {
	t.Helper()
	if r.State != state || r.Reason != reason {
		t.Fatalf("state=%q reason=%q error=%q, want state=%q reason=%q", r.State, r.Reason, r.Error, state, reason)
	}
}

// ── Decision logic ──────────────────────────────────────────────────────────

func TestObliReachNoTargetNoReport(t *testing.T) {
	h := newReachHarness(t, true)
	h.m.Reconcile()
	if r := h.m.Report(); r != nil {
		t.Fatalf("report before any target: %+v", r)
	}
	h.m.SetDesired(h.desired())
	h.ops.probe = h.alignedProbe("1.0.198", true)
	h.run()
	h.m.SetDesired(nil) // older server / block absent → idle, nothing reported
	if r := h.m.Report(); r != nil {
		t.Fatalf("report after target removed: %+v", r)
	}
}

func TestObliReachAlignedNoAction(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.198", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStateUpToDate, "")
	if h.downloads() != 0 || len(h.ops.installs) != 0 || h.ops.starts != 0 {
		t.Fatalf("aligned: downloads=%d installs=%d starts=%d", h.downloads(), len(h.ops.installs), h.ops.starts)
	}
	if r.InstalledVersion != "1.0.198" || r.DesiredVersion != "1.0.198" || !r.Running || r.Attempts != 0 {
		t.Fatalf("report %+v", r)
	}
}

func TestObliReachMissingInstallsAfterSpread(t *testing.T) {
	h := newReachHarness(t, true)
	h.m.SetDesired(h.desired())
	spread := h.m.spread()
	if spread <= 0 || spread >= orMissingSpread*time.Second {
		t.Fatalf("spread out of range: %s", spread)
	}
	r := h.run()
	expectState(t, r, orStatePending, orReasonSpread)
	if h.downloads() != 0 {
		t.Fatalf("downloaded during the spread")
	}
	h.advance(spread + time.Second)
	r = h.run()
	expectState(t, r, orStateUpToDate, "")
	if h.downloads() != 1 || len(h.ops.installs) != 1 || h.ops.installs[0].uninstallFirst {
		t.Fatalf("downloads=%d installs=%+v", h.downloads(), h.ops.installs)
	}
	if h.ops.installs[0].sha != h.sha || r.InstalledVersion != "1.0.198" {
		t.Fatalf("install %+v report %+v", h.ops.installs[0], r)
	}
	if h.notifies == 0 {
		t.Fatalf("state changes must trigger an immediate push")
	}
	// The same spread applies again only from agent start: stable per device.
	h2 := newReachHarness(t, true)
	if h2.m.spread() != spread {
		t.Fatalf("spread not stable for the same device")
	}
}

func TestObliReachPrivacyDeferredNoDownload(t *testing.T) {
	h := newReachHarness(t, true)
	h.privacy = true
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStatePrivacyDeferred, "")
	h.advance(time.Hour)
	h.run()
	if h.downloads() != 0 || len(h.ops.installs) != 0 {
		t.Fatalf("privacy mode: downloads=%d installs=%d", h.downloads(), len(h.ops.installs))
	}
	if h.ops.enforces == 0 {
		t.Fatalf("privacy invariant not enforced during reconcile")
	}
	// Installed + aligned under privacy: up to date, expected to be stopped.
	h.ops.probe = h.alignedProbe("1.0.198", true)
	r = h.run()
	expectState(t, r, orStateUpToDate, "")
	if r.Running || h.ops.starts != 0 {
		t.Fatalf("ObliReach must stay stopped under privacy: %+v starts=%d", r, h.ops.starts)
	}
	// Manual install is refused too.
	if _, err := h.m.InstallNow(obliReachServer{}, false); err == nil || !strings.Contains(err.Error(), "privacy") {
		t.Fatalf("InstallNow under privacy: %v", err)
	}
}

func TestObliReachPrivacyTurnedOnDuringInstall(t *testing.T) {
	// a) privacy goes on after download/verification → no installer run.
	h := newReachHarness(t, true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.ops.onVerify = func() { h.privacy = true }
	r := h.run()
	expectState(t, r, orStatePrivacyDeferred, "")
	if len(h.ops.installs) != 0 || r.Attempts != 0 {
		t.Fatalf("installer ran / failure counted: installs=%d attempts=%d", len(h.ops.installs), r.Attempts)
	}

	// b) privacy goes on while the installer runs → stopped right after.
	h2 := newReachHarness(t, true)
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	h2.ops.onInstall = func() { h2.privacy = true }
	r = h2.run()
	if len(h2.ops.installs) != 1 || h2.ops.stops != 1 {
		t.Fatalf("installs=%d stops=%d", len(h2.ops.installs), h2.ops.stops)
	}
	expectState(t, r, orStateUpToDate, "")
	if r.Running {
		t.Fatalf("ObliReach left running under privacy")
	}

	// c) Unix: the manager launches it itself — never under privacy.
	h3 := newReachHarness(t, false)
	h3.m.SetDesired(h3.desired())
	h3.afterSpread()
	h3.ops.onInstall = func() { h3.privacy = true }
	h3.run()
	if h3.ops.starts != 0 || h3.ops.stops != 1 {
		t.Fatalf("unix: starts=%d stops=%d", h3.ops.starts, h3.ops.stops)
	}
}

func TestObliReachPrivacyTick(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.198", true)
	h.m.PrivacyTick(false)
	if h.ops.enforces != 0 {
		t.Fatalf("privacy off: nothing to enforce")
	}
	h.privacy = true
	h.m.PrivacyTick(false)
	if h.ops.enforces != 1 || h.ops.probe.Running {
		t.Fatalf("privacy on: ObliReach not stopped (enforces=%d)", h.ops.enforces)
	}
	// Works even without any target from the server (older server).
	if h.m.Report() != nil {
		t.Fatalf("unexpected report")
	}
}

func TestObliReachDowngradeUninstallsFirst(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.200", true) // server rolled back to 1.0.198
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStatePending, orReasonGrace)
	h.advance(orMismatchGrace)
	r = h.run()
	expectState(t, r, orStateUpToDate, "")
	if len(h.ops.installs) != 1 || !h.ops.installs[0].uninstallFirst {
		t.Fatalf("downgrade must uninstall first: %+v", h.ops.installs)
	}
}

func TestObliReachShaMismatchBackoff(t *testing.T) {
	h := newReachHarness(t, true)
	d := h.desired()
	d.SHA256 = strings.Repeat("ab", 32) // valid format, wrong content
	h.m.SetDesired(d)
	h.afterSpread()
	want := []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, 60 * time.Minute, 60 * time.Minute}
	for i, delay := range want {
		r := h.run()
		expectState(t, r, orStateFailed, "")
		if !strings.HasPrefix(r.Error, "sha256_mismatch") || r.Attempts != i+1 {
			t.Fatalf("attempt %d: %+v", i+1, r)
		}
		next, err := time.Parse(time.RFC3339, r.NextAttemptAt)
		if err != nil || !next.Equal(h.now.Add(delay)) {
			t.Fatalf("attempt %d: next=%s want now+%s", i+1, r.NextAttemptAt, delay)
		}
		if len(h.ops.installs) != 0 {
			t.Fatalf("installer ran on a corrupt download")
		}
		// Before the deadline: no new download.
		hits := h.downloads()
		h.advance(delay - time.Second)
		r = h.run()
		expectState(t, r, orStateFailed, orReasonBackoff)
		if h.downloads() != hits {
			t.Fatalf("downloaded during backoff")
		}
		h.advance(time.Second)
	}
}

func TestObliReachBackoffJitterAndPersistence(t *testing.T) {
	h := newReachHarness(t, true)
	h.env.jitter = func() float64 { return 1 }
	h.m = newObliReachManager(h.ops, h.env, h.statePath)
	d := h.desired()
	d.SHA256 = strings.Repeat("cd", 32)
	h.m.SetDesired(d)
	h.afterSpread()
	r := h.run()
	next, _ := time.Parse(time.RFC3339, r.NextAttemptAt)
	if got := next.Sub(h.now); got != 2*time.Minute+12*time.Second {
		t.Fatalf("jitter +10%%: got %s", got)
	}
	// Agent restart: a new manager reloads the backoff and does not hammer.
	hits := h.downloads()
	m2 := newObliReachManager(h.ops, h.env, h.statePath)
	m2.SetDesired(d)
	h.advance(time.Minute)
	m2.Reconcile()
	r2 := m2.Report()
	if r2 == nil || r2.State != orStateFailed || r2.Reason != orReasonBackoff || r2.Attempts != 1 || h.downloads() != hits {
		t.Fatalf("backoff not persisted: %+v downloads=%d", r2, h.downloads())
	}
}

func TestObliReachTargetChangeResetsBackoff(t *testing.T) {
	h := newReachHarness(t, true)
	bad := h.desired()
	bad.SHA256 = strings.Repeat("ef", 32)
	h.m.SetDesired(bad)
	h.afterSpread()
	h.run()
	h.advance(2 * time.Minute)
	r := h.run()
	if r.Attempts != 2 {
		t.Fatalf("attempts=%d", r.Attempts)
	}
	// New build published (correct hash): fresh start, no waiting.
	good := h.desired()
	good.Version = "1.0.199"
	h.m.SetDesired(good)
	h.advance(time.Second)
	r = h.run()
	expectState(t, r, orStateUpToDate, "")
	if r.Attempts != 0 || len(h.ops.installs) != 1 || h.ops.installs[0].version != "1.0.199" {
		t.Fatalf("report %+v installs %+v", r, h.ops.installs)
	}
}

func TestObliReachBusyNoAttemptCounted(t *testing.T) {
	h := newReachHarness(t, true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.ops.busy = orReasonBusyMSI
	r := h.run()
	expectState(t, r, orStatePending, orReasonBusyMSI)
	h.ops.busy = ""
	h.agentBusy = true
	r = h.run()
	expectState(t, r, orStatePending, orReasonBusyAgentUpd)
	if h.downloads() != 0 || r.Attempts != 0 {
		t.Fatalf("busy: downloads=%d attempts=%d", h.downloads(), r.Attempts)
	}
	// msiexec answering 1618 (another install started meanwhile).
	h.agentBusy = false
	h.ops.installErr = &orError{Busy: orReasonBusyMSI}
	r = h.run()
	expectState(t, r, orStatePending, orReasonBusyMSI)
	if r.Attempts != 0 {
		t.Fatalf("1618 counted as a failure")
	}
}

func TestObliReachDisabled(t *testing.T) {
	h := newReachHarness(t, true)
	d := h.desired()
	d.Enabled = false
	h.m.SetDesired(d)
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStateDisabled, "")
	if h.downloads() != 0 || len(h.ops.installs) != 0 || h.ops.starts != 0 || h.ops.stops != 0 {
		t.Fatalf("disabled must not act (and never uninstalls)")
	}
}

func TestObliReachManifestValidation(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(h *reachHarness, d *ObliReachDesired)
		state   string
		errCode string
	}{
		{"no artifact", func(h *reachHarness, d *ObliReachDesired) { d.File = "" }, orStateUnsupported, "no_artifact"},
		{"platform", func(h *reachHarness, d *ObliReachDesired) { h.ops.artifact = "" }, orStateUnsupported, "platform"},
		{"wrong file", func(h *reachHarness, d *ObliReachDesired) { d.File = "oblireach-agent.exe" }, orStateFailed, "bad_manifest"},
		{"traversal", func(h *reachHarness, d *ObliReachDesired) { d.File = "../../etc/passwd" }, orStateFailed, "bad_manifest"},
		{"bad version", func(h *reachHarness, d *ObliReachDesired) { d.Version = "1.0" }, orStateFailed, "bad_manifest"},
		{"bad sha", func(h *reachHarness, d *ObliReachDesired) { d.SHA256 = "xyz" }, orStateFailed, "bad_manifest"},
		{"zero size", func(h *reachHarness, d *ObliReachDesired) { d.Size = 0 }, orStateFailed, "bad_manifest"},
		{"huge size", func(h *reachHarness, d *ObliReachDesired) { d.Size = orMaxArtifactSize + 1 }, orStateFailed, "bad_manifest"},
		{"no display", func(h *reachHarness, d *ObliReachDesired) { h.ops.precond = "no_display: none" }, orStateUnsupported, "no_display"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newReachHarness(t, false)
			d := h.desired()
			c.mut(h, d)
			h.m.SetDesired(d)
			h.afterSpread()
			r := h.run()
			if r.State != c.state || !strings.HasPrefix(r.Error, c.errCode) {
				t.Fatalf("state=%q error=%q, want %q %q", r.State, r.Error, c.state, c.errCode)
			}
			if h.downloads() != 0 || r.Attempts != 0 {
				t.Fatalf("acted on an invalid manifest")
			}
		})
	}
	// Uppercase hash from the server is normalised, not rejected.
	h := newReachHarness(t, false)
	d := h.desired()
	d.SHA256 = strings.ToUpper(d.SHA256)
	h.m.SetDesired(d)
	h.afterSpread()
	expectState(t, h.run(), orStateUpToDate, "")
}

func TestObliReachWindowsSelfUpdateGrace(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true) // older, running: ObliReach updates itself
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStatePending, orReasonSelfUpdate)
	h.advance(orSelfUpdateGrace - time.Minute)
	expectState(t, h.run(), orStatePending, orReasonSelfUpdate)
	if h.downloads() != 0 {
		t.Fatalf("fought ObliReach's self-update")
	}
	h.advance(time.Minute)
	r = h.run()
	expectState(t, r, orStateUpToDate, "")
	if len(h.ops.installs) != 1 || h.ops.installs[0].uninstallFirst {
		t.Fatalf("upgrade after grace: %+v", h.ops.installs)
	}

	// Older but NOT running: nothing will self-update → short grace.
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.197", false)
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	expectState(t, h2.run(), orStatePending, orReasonGrace)
	h2.advance(orMismatchGrace)
	expectState(t, h2.run(), orStateUpToDate, "")

	// Unix: no self-update, hash mismatch → short grace.
	h3 := newReachHarness(t, false)
	h3.ops.probe = h3.alignedProbe("1.0.197", true)
	h3.ops.probe.Hash = strings.Repeat("00", 32)
	h3.m.SetDesired(h3.desired())
	h3.afterSpread()
	expectState(t, h3.run(), orStatePending, orReasonGrace)
	h3.advance(orMismatchGrace)
	expectState(t, h3.run(), orStateUpToDate, "")
	if h3.ops.starts != 1 {
		t.Fatalf("unix: ObliReach must be launched after install (starts=%d)", h3.ops.starts)
	}
}

func TestObliReachHold(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.200", true)
	d := h.desired()
	d.Hold = true // a remote session is active
	h.m.SetDesired(d)
	h.afterSpread()
	expectState(t, h.run(), orStatePending, orReasonHold)
	h.advance(time.Hour) // well past the grace: still held
	expectState(t, h.run(), orStatePending, orReasonHold)
	if h.downloads() != 0 {
		t.Fatalf("reinstalled during a remote session")
	}
	d.Hold = false
	h.m.SetDesired(d)
	expectState(t, h.run(), orStateUpToDate, "")

	// Missing: hold does not block a fresh install.
	h2 := newReachHarness(t, true)
	d2 := h2.desired()
	d2.Hold = true
	h2.m.SetDesired(d2)
	h2.afterSpread()
	expectState(t, h2.run(), orStateUpToDate, "")
}

func TestObliReachStartWhenNotRunningThenRepair(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.198", false)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStateUpToDate, "")
	if r.Running || h.ops.starts != 0 {
		t.Fatalf("started before the not-running grace")
	}
	h.advance(5 * time.Minute)
	r = h.run()
	expectState(t, r, orStateUpToDate, "")
	if h.ops.starts != 1 || !r.Running {
		t.Fatalf("not started after grace: starts=%d %+v", h.ops.starts, r)
	}

	// Start keeps failing: 3 failures in a row → reinstall (uninstall first).
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.198", false)
	h2.ops.startErr = orErr("start_failed", "access denied")
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	h2.run()
	h2.advance(5 * time.Minute)
	for i, next := range []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute} {
		r := h2.run()
		expectState(t, r, orStateFailed, "")
		if !strings.HasPrefix(r.Error, "start_failed") || h2.ops.starts != i+1 {
			t.Fatalf("start failure %d: %+v starts=%d", i+1, r, h2.ops.starts)
		}
		h2.advance(next)
	}
	h2.ops.startErr = nil
	r = h2.run()
	expectState(t, r, orStateUpToDate, "")
	if len(h2.ops.installs) != 1 || !h2.ops.installs[0].uninstallFirst {
		t.Fatalf("repair must reinstall: %+v", h2.ops.installs)
	}
	// The repair alone does not clear the backoff: only ObliReach still
	// running orConfirmRunning later does.
	if r.Attempts != 3 {
		t.Fatalf("attempts cleared by the repair itself: %d", r.Attempts)
	}
	h2.advance(time.Minute)
	if r = h2.run(); r.Attempts != 3 || !r.Running {
		t.Fatalf("attempts cleared before confirmation: %+v", r)
	}
	h2.advance(orConfirmRunning)
	r = h2.run()
	expectState(t, r, orStateUpToDate, "")
	if r.Attempts != 0 || r.NextAttemptAt != "" {
		t.Fatalf("attempts not reset once confirmed running: %+v", r)
	}
}

// actionLog records when the manager started or (re)installed ObliReach.
type actionLog struct {
	h         *reachHarness
	lastStart int
	lastInst  int
	times     []time.Time
}

func (a *actionLog) observe() bool {
	acted := a.h.ops.starts != a.lastStart || len(a.h.ops.installs) != a.lastInst
	if acted {
		a.times = append(a.times, a.h.now)
	}
	a.lastStart, a.lastInst = a.h.ops.starts, len(a.h.ops.installs)
	return acted
}

// OR-1: a build that dies right after every start (and right after the MSI
// started it) must keep escalating to one action per hour — neither a
// "successful" start nor a successful repair reinstall restarts the ladder.
func TestObliReachCrashAfterStartKeepsEscalating(t *testing.T) {
	for _, c := range []struct {
		name     string
		windows  bool
		startErr error
	}{
		{"windows start reports exited", true, &orError{Code: "exited_immediately", Detail: "service stopped right after start"}},
		{"windows dies after the confirmation", true, nil},
		{"unix dies after the confirmation", false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newReachHarness(t, c.windows)
			h.ops.probe = h.alignedProbe("1.0.198", false)
			h.ops.startErr = c.startErr
			h.m.SetDesired(h.desired())
			h.afterSpread()
			a := &actionLog{h: h}
			for i := 0; i < 6*60; i++ {
				h.m.Reconcile()
				a.observe()
				h.ops.probe.Running = false // dead by the next round
				h.advance(time.Minute)
			}
			if h.downloads() > 4 || len(h.ops.installs) > 4 {
				t.Fatalf("6h: downloads=%d installs=%d (reinstall loop)", h.downloads(), len(h.ops.installs))
			}
			if len(a.times) > 12 {
				t.Fatalf("6h: %d starts/installs (restart loop): %v", len(a.times), a.times)
			}
			// After the ramp (2/5/15/30 min): at most one action per hour.
			for i := 6; i < len(a.times); i++ {
				if gap := a.times[i].Sub(a.times[i-1]); gap < time.Hour {
					t.Fatalf("action %d only %s after the previous one: %v", i, gap, a.times)
				}
			}
			r := h.m.Report()
			if r == nil || r.Attempts < 6 {
				t.Fatalf("attempts did not escalate: %+v", r)
			}
			t.Logf("6h: downloads=%d installs=%d starts=%d attempts=%d", h.downloads(), len(h.ops.installs), h.ops.starts, r.Attempts)

			// Fixed (e.g. the crash was environmental): once it stays up
			// orConfirmRunning after a start, the ladder is cleared.
			h.ops.startErr = nil
			for i := 0; i < 3*60 && h.m.Report().Attempts != 0; i++ {
				h.m.Reconcile()
				h.advance(time.Minute)
			}
			if r := h.m.Report(); r.Attempts != 0 || r.State != orStateUpToDate || !r.Running {
				t.Fatalf("backoff not cleared once running stably: %+v", r)
			}
		})
	}
}

// OR-1: a start that "succeeds" and a process still running on the next rounds
// but gone before orConfirmRunning counts as a failed start.
func TestObliReachExitedAfterStartCounted(t *testing.T) {
	h := newReachHarness(t, false)
	h.ops.probe = h.alignedProbe("1.0.198", false)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.run()
	h.advance(time.Minute)
	h.run() // started
	if h.ops.starts != 1 {
		t.Fatalf("starts=%d", h.ops.starts)
	}
	h.advance(3 * time.Minute)
	if r := h.run(); r.State != orStateUpToDate || r.Attempts != 0 {
		t.Fatalf("running: %+v", r)
	}
	h.ops.probe.Running = false
	h.advance(time.Minute)
	r := h.run()
	expectState(t, r, orStateFailed, "")
	if !strings.HasPrefix(r.Error, "exited_after_start") || r.Attempts != 1 {
		t.Fatalf("%+v", r)
	}
	// A pending service (still starting) is not a crash.
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.198", false)
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	h2.run()
	h2.advance(5 * time.Minute)
	h2.run() // started
	h2.ops.probe.Running, h2.ops.probe.Pending = false, true
	h2.advance(time.Minute)
	if r := h2.run(); r.Attempts != 0 || strings.HasPrefix(r.Error, "exited_after_start") {
		t.Fatalf("pending counted as a crash: %+v", r)
	}
}

// OR-3: the installer found busy AFTER the download (msiexec 1618, MSI mutex
// taken meanwhile) must not re-download every round.
func TestObliReachBusyAfterDownloadBacksOff(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.ops.installErr = &orError{Busy: orReasonBusyMSI}
	h.m.SetDesired(h.desired())
	h.afterSpread()
	expectState(t, h.run(), orStatePending, orReasonSelfUpdate)
	h.advance(orSelfUpdateGrace)
	start := h.now
	var tries []time.Duration
	for i := 0; i < 60; i++ {
		before := h.downloads()
		r := h.run()
		if r.State != orStatePending || r.Reason != orReasonBusyMSI || r.Attempts != 0 {
			t.Fatalf("minute %d: %+v (busy is not a failure)", i, r)
		}
		if h.downloads() != before {
			tries = append(tries, h.now.Sub(start))
		} else if r.NextAttemptAt == "" {
			t.Fatalf("minute %d: the busy retry time is not reported: %+v", i, r)
		}
		h.advance(time.Minute)
	}
	// Short ladder (1/2/3/5/5 min, then every 5 min): never a download per
	// round, never an hour behind a transient installer.
	wantTries := []time.Duration{0, time.Minute, 3 * time.Minute, 6 * time.Minute, 11 * time.Minute, 16 * time.Minute}
	if len(tries) < len(wantTries) {
		t.Fatalf("busy retries at %v", tries)
	}
	for i, w := range wantTries {
		if tries[i] != w {
			t.Fatalf("busy retry %d at +%s, want +%s (all: %v)", i, tries[i], w, tries)
		}
	}
	if h.downloads() > 14 {
		t.Fatalf("1h busy-after-download: %d downloads", h.downloads())
	}
	// Persisted across an agent restart.
	hits := h.downloads()
	m2 := newObliReachManager(h.ops, h.env, h.statePath)
	m2.SetDesired(h.desired())
	m2.Reconcile()
	if h.downloads() != hits {
		t.Fatalf("busy retry not persisted")
	}
	// Installer free again: installed at the next retry, retry state cleared.
	h.ops.installErr = nil
	h.advance(time.Hour)
	r := h.run()
	expectState(t, r, orStateUpToDate, "")
	if h.m.st.BusyRetries != 0 || !h.m.st.NextBusyAt.IsZero() {
		t.Fatalf("busy retry not cleared on success: %+v", h.m.st)
	}

	// A new target starts afresh (the busy retry is dropped).
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.197", false)
	h2.ops.installErr = &orError{Busy: orReasonBusyMSI}
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	h2.run()
	h2.advance(orMismatchGrace)
	expectState(t, h2.run(), orStatePending, orReasonBusyMSI)
	if len(h2.ops.installs) != 1 || h2.m.st.NextBusyAt.IsZero() {
		t.Fatalf("installs=%d nextBusyAt=%s", len(h2.ops.installs), h2.m.st.NextBusyAt)
	}
	d := h2.desired()
	d.Version = "1.0.199"
	h2.m.SetDesired(d)
	h2.run()
	if h2.m.st.BusyRetries != 0 || !h2.m.st.NextBusyAt.IsZero() {
		t.Fatalf("busy retry kept across a target change: %+v", h2.m.st)
	}
}

func TestObliReachUnixExitedImmediately(t *testing.T) {
	h := newReachHarness(t, false)
	h.ops.startErr = orErr("exited_immediately", "boom")
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStateFailed, "")
	if !strings.HasPrefix(r.Error, "exited_immediately") || r.Attempts != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestObliReachMsi1638ForcesUninstall(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", false)
	h.ops.installErr = &orError{Code: "msi_exit_1638", ForceUninstall: true}
	h.m.SetDesired(h.desired())
	h.afterSpread()
	expectState(t, h.run(), orStatePending, orReasonGrace)
	h.advance(orMismatchGrace)
	r := h.run()
	expectState(t, r, orStateFailed, "")
	if !strings.HasPrefix(r.Error, "msi_exit_1638") || len(h.ops.installs) != 1 || h.ops.installs[0].uninstallFirst {
		t.Fatalf("%+v %+v", r, h.ops.installs)
	}
	h.ops.installErr = nil
	h.advance(2 * time.Minute)
	expectState(t, h.run(), orStateUpToDate, "")
	if len(h.ops.installs) != 2 || !h.ops.installs[1].uninstallFirst {
		t.Fatalf("1638 must force an uninstall next time: %+v", h.ops.installs)
	}
}

func TestObliReachSignatureFailure(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.sigErr = &orError{Code: "signer_mismatch", Detail: `signed by "Mallory"`}
	h.m.SetDesired(h.desired())
	h.afterSpread()
	r := h.run()
	expectState(t, r, orStateFailed, "")
	if !strings.HasPrefix(r.Error, "signer_mismatch") || len(h.ops.installs) != 0 {
		t.Fatalf("%+v installs=%d", r, len(h.ops.installs))
	}
	if len(h.m.st.StagingDir) == 0 {
		t.Fatalf("installer logs folder not remembered for cleanup")
	}
	// Next attempt discards the previous staging folder first.
	h.advance(2 * time.Minute)
	h.run()
	if len(h.ops.discarded) != 1 {
		t.Fatalf("previous staging folder not discarded: %v", h.ops.discarded)
	}
}

func TestObliReachDownloadErrors(t *testing.T) {
	// HTTP error from the server.
	h := newReachHarness(t, true)
	h.ops.artifact = "oblireach-agent.msi"
	d := h.desired()
	h.m.SetDesired(d)
	h.afterSpread()
	h.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	r := h.run()
	if r.State != orStateFailed || r.Error != "http_503" {
		t.Fatalf("%+v", r)
	}
	// Redirects are never followed (only the enrolled server is trusted).
	h.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/evil.msi", http.StatusFound)
	})
	h.advance(2 * time.Minute)
	r = h.run()
	if r.Error != "http_302" {
		t.Fatalf("redirect: %+v", r)
	}
	// Truncated / oversized body.
	h.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(append(h.payload, 'x'))
	})
	h.advance(5 * time.Minute)
	r = h.run()
	if !strings.HasPrefix(r.Error, "size_mismatch") {
		t.Fatalf("size: %+v", r)
	}
	if len(h.ops.installs) != 0 {
		t.Fatalf("installer ran after a failed download")
	}
}

func TestObliReachInstallNow(t *testing.T) {
	// Ignores backoff, resets attempts, full reinstall when present.
	h := newReachHarness(t, true)
	d := h.desired()
	d.SHA256 = strings.Repeat("aa", 32)
	h.m.SetDesired(d)
	h.afterSpread()
	h.run()
	h.run() // still in backoff
	h.m.SetDesired(h.desired())
	h.m.st.Attempts, h.m.st.NextAttemptAt = 4, h.now.Add(time.Hour) // pretend a long backoff
	h.ops.probe = h.alignedProbe("1.0.198", true)
	res, err := h.m.InstallNow(obliReachServer{URL: h.srv.URL, APIKey: "test-key"}, false)
	if err != nil {
		t.Fatalf("InstallNow: %v", err)
	}
	if m, _ := res.(map[string]interface{}); m["status"] != "installed" || m["method"] != "msi" {
		t.Fatalf("result %+v", res)
	}
	if len(h.ops.installs) != 1 || !h.ops.installs[0].uninstallFirst {
		t.Fatalf("manual install must repair (uninstall first): %+v", h.ops.installs)
	}
	if r := h.m.Report(); r.Attempts != 0 || r.State != orStateUpToDate {
		t.Fatalf("report %+v", r)
	}

	// No manifest yet (older server): X-Content-SHA256 header is mandatory.
	h2 := newReachHarness(t, false)
	if _, err := h2.m.InstallNow(obliReachServer{URL: h2.srv.URL, APIKey: "test-key"}, false); err != nil {
		t.Fatalf("fallback install: %v", err)
	}
	if len(h2.ops.installs) != 1 || h2.ops.installs[0].sha != h2.sha {
		t.Fatalf("fallback install %+v", h2.ops.installs)
	}
	h3 := newReachHarness(t, false)
	h3.noHeader = true
	_, err = h3.m.InstallNow(obliReachServer{URL: h3.srv.URL, APIKey: "test-key"}, false)
	if err == nil || !strings.HasPrefix(err.Error(), "no_hash") || len(h3.ops.installs) != 0 {
		t.Fatalf("no hash must refuse: %v", err)
	}

	// Unsupported platform.
	h4 := newReachHarness(t, false)
	h4.ops.artifact = ""
	if _, err := h4.m.InstallNow(obliReachServer{URL: h4.srv.URL}, false); err == nil {
		t.Fatalf("unsupported platform accepted")
	}

	// Concurrent install refused instead of queued behind a 10-min msiexec.
	h5 := newReachHarness(t, true)
	h5.m.opMu.Lock()
	_, err = h5.m.InstallNow(obliReachServer{URL: h5.srv.URL, APIKey: "test-key"}, false)
	h5.m.opMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("concurrent InstallNow: %v", err)
	}
}

// The "Update Reach" button (install_oblireach {mode:"upgrade"}): an UPDATE,
// never the uninstall-then-install of the repair action — a new build that
// fails to install must leave the old one in place (and running).
func TestObliReachInstallNowUpgrade(t *testing.T) {
	srvOf := func(h *reachHarness) obliReachServer { return obliReachServer{URL: h.srv.URL, APIKey: "test-key"} }

	// Older build running → plain `msiexec /i` (no uninstall first).
	h := newReachHarness(t, true)
	h.m.SetDesired(h.desired())
	h.ops.probe = h.alignedProbe("1.0.197", true)
	res, err := h.m.InstallNow(srvOf(h), true)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if m, _ := res.(map[string]interface{}); m["status"] != "installed" {
		t.Fatalf("result %+v", res)
	}
	if len(h.ops.installs) != 1 || h.ops.installs[0].uninstallFirst {
		t.Fatalf("an update must not uninstall first: %+v", h.ops.installs)
	}

	// Already the server's build → nothing installed, nothing downloaded.
	h2 := newReachHarness(t, true)
	h2.m.SetDesired(h2.desired())
	h2.ops.probe = h2.alignedProbe("1.0.198", true)
	res, err = h2.m.InstallNow(srvOf(h2), true)
	if m, _ := res.(map[string]interface{}); err != nil || m["status"] != "up_to_date" || m["version"] != "1.0.198" {
		t.Fatalf("up to date: %+v %v", res, err)
	}
	if len(h2.ops.installs) != 0 || h2.downloads() != 0 {
		t.Fatalf("up to date: installs=%d downloads=%d", len(h2.ops.installs), h2.downloads())
	}
	// … while the repair action still reinstalls it.
	if _, err := h2.m.InstallNow(srvOf(h2), false); err != nil || len(h2.ops.installs) != 1 || !h2.ops.installs[0].uninstallFirst {
		t.Fatalf("repair: %v %+v", err, h2.ops.installs)
	}

	// Downgrade (server ships an older build) → the MSI refuses it: uninstall first.
	h3 := newReachHarness(t, true)
	h3.m.SetDesired(h3.desired())
	h3.ops.probe = h3.alignedProbe("1.0.300", true)
	if _, err := h3.m.InstallNow(srvOf(h3), true); err != nil || len(h3.ops.installs) != 1 || !h3.ops.installs[0].uninstallFirst {
		t.Fatalf("downgrade: %v %+v", err, h3.ops.installs)
	}

	// The new build fails (msiexec 1603, rolled back) and the installer left
	// the old service stopped → it is started again (remote access kept).
	h4 := newReachHarness(t, true)
	h4.m.SetDesired(h4.desired())
	h4.ops.probe = h4.alignedProbe("1.0.197", true)
	h4.ops.onInstall = func() { h4.ops.probe.Running = false }
	h4.ops.installErr = orErr("msi_exit_1603", "see install.log")
	if _, err := h4.m.InstallNow(srvOf(h4), true); err == nil || !strings.HasPrefix(err.Error(), "msi_exit_1603") {
		t.Fatalf("failed upgrade must report the msiexec error: %v", err)
	}
	if h4.ops.starts != 1 || !h4.ops.probe.Running || h4.ops.probe.Version != "1.0.197" || h4.ops.installs[0].uninstallFirst {
		t.Fatalf("old build not restarted after the failed update: starts=%d probe=%+v installs=%+v", h4.ops.starts, h4.ops.probe, h4.ops.installs)
	}
	if r := h4.m.Report(); r == nil || r.State != orStateFailed {
		t.Fatalf("failure must be reported: %+v", r)
	}
	// Still running after a failure → not touched.
	h5 := newReachHarness(t, true)
	h5.m.SetDesired(h5.desired())
	h5.ops.probe = h5.alignedProbe("1.0.197", true)
	h5.ops.installErr = orErr("msi_exit_1603", "see install.log")
	_, _ = h5.m.InstallNow(srvOf(h5), true)
	if h5.ops.starts != 0 {
		t.Fatalf("running build restarted: starts=%d", h5.ops.starts)
	}

	// An install already running: a neutral answer, not an error.
	h6 := newReachHarness(t, true)
	h6.m.SetDesired(h6.desired())
	h6.ops.probe = h6.alignedProbe("1.0.197", true)
	h6.m.opMu.Lock()
	res, err = h6.m.InstallNow(srvOf(h6), true)
	h6.m.opMu.Unlock()
	if m, _ := res.(map[string]interface{}); err != nil || m["status"] != "in_progress" {
		t.Fatalf("concurrent upgrade: %+v %v", res, err)
	}
	if len(h6.ops.installs) != 0 {
		t.Fatalf("concurrent upgrade installed")
	}

	// Payload wiring: {mode:"upgrade"} → update, anything else → repair.
	for _, c := range []struct {
		payload map[string]interface{}
		repair  bool
	}{{map[string]interface{}{"mode": "upgrade"}, false}, {nil, true}, {map[string]interface{}{"mode": "other"}, true}} {
		hc := newReachHarness(t, true)
		hc.m.SetDesired(hc.desired())
		hc.ops.probe = hc.alignedProbe("1.0.197", true)
		saved := obliReachMgr
		obliReachMgr = hc.m
		d := &CommandDispatcher{serverURL: hc.srv.URL, apiKey: "test-key"}
		_, err := d.handleInstallOblireach(AgentCommand{ID: "c1", Type: "install_oblireach", Payload: c.payload})
		obliReachMgr = saved
		if err != nil || len(hc.ops.installs) != 1 || hc.ops.installs[0].uninstallFirst != c.repair {
			t.Fatalf("payload %v: err=%v installs=%+v", c.payload, err, hc.ops.installs)
		}
	}
}

// A pending state after the failure backoff ended must not report the past
// backoff end as its next attempt.
func TestObliReachNextAttemptNeverInThePast(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", false)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.ops.installErr = orErr("msi_exit_1603", "see install.log")
	expectState(t, h.run(), orStatePending, orReasonGrace) // mismatch clock starts
	h.advance(orMismatchGrace + time.Minute)
	r := h.run()
	expectState(t, r, orStateFailed, "")
	if r.NextAttemptAt == "" {
		t.Fatalf("backoff end not reported")
	}
	expectState(t, h.run(), orStateFailed, orReasonBackoff)
	h.advance(time.Hour) // backoff over
	h.ops.busy = orReasonBusyMSI
	r = h.run()
	expectState(t, r, orStatePending, orReasonBusyMSI)
	if r.NextAttemptAt != "" {
		t.Fatalf("past backoff end reported as the next attempt: %q (now %s)", r.NextAttemptAt, h.now.Format(time.RFC3339))
	}
}

func TestObliReachReportJSONShape(t *testing.T) {
	h := newReachHarness(t, true)
	d := h.desired()
	d.SHA256 = strings.Repeat("12", 32)
	h.m.SetDesired(d)
	h.afterSpread()
	r := h.run()
	b, _ := json.Marshal(pushBody{Oblireach: r})
	var body map[string]json.RawMessage
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	var o map[string]interface{}
	if err := json.Unmarshal(body["oblireach"], &o); err != nil {
		t.Fatalf("oblireach block: %v (%s)", err, b)
	}
	for _, k := range []string{"state", "installedVersion", "desiredVersion", "running", "reason", "error", "attempts", "nextAttemptAt", "lastAttemptAt", "since"} {
		if _, ok := o[k]; !ok {
			t.Fatalf("A2 field %q missing in %s", k, b)
		}
	}
	if len(r.Error) > orMaxErrorLen {
		t.Fatalf("error too long")
	}
	// The response block decodes into the A1 type.
	var resp pushResponse
	raw := `{"status":"ok","oblireach":{"enabled":true,"version":"1.0.198","file":"oblireach-agent.msi","sha256":"` + h.sha + `","size":7921664,"hold":false}}`
	if err := json.Unmarshal([]byte(raw), &resp); err != nil || resp.Oblireach == nil || resp.Oblireach.Size != 7921664 || !resp.Oblireach.Enabled {
		t.Fatalf("A1 decode: %v %+v", err, resp.Oblireach)
	}
	// Absent block → nil (older server).
	var old pushResponse
	_ = json.Unmarshal([]byte(`{"status":"ok"}`), &old)
	if old.Oblireach != nil {
		t.Fatalf("absent block must decode as nil")
	}
	// No report → field omitted from the push body.
	b, _ = json.Marshal(pushBody{})
	if strings.Contains(string(b), `"oblireach"`) {
		t.Fatalf("empty report must be omitted: %s", b)
	}
}

// ── Privacy mode turned off (PrivacyReleased) ───────────────────────────────

// underPrivacy runs one round a minute for d with privacy mode on (the rounds
// stop + disable ObliReach, and stamp the mismatch).
func (h *reachHarness) underPrivacy(d time.Duration) {
	h.t.Helper()
	h.privacy = true
	for elapsed := time.Duration(0); elapsed < d; elapsed += time.Minute {
		h.m.Reconcile()
		h.advance(time.Minute)
	}
	if r := h.m.Report(); r != nil && r.State != orStatePrivacyDeferred && r.State != orStateUpToDate {
		h.t.Fatalf("under privacy: %+v", r)
	}
}

// release turns privacy mode off and runs the manager's privacy release.
func (h *reachHarness) release() *ObliReachReport {
	h.t.Helper()
	h.privacy = false
	h.m.PrivacyReleased()
	r := h.m.Report()
	if r == nil {
		h.t.Fatalf("no report after the privacy release")
	}
	return r
}

func (h *reachHarness) kicked() bool {
	select {
	case <-h.m.kickCh:
		return true
	default:
		return false
	}
}

// The reported case: privacy mode on for a while, a newer ObliReach
// published meanwhile, privacy mode off → the verified install runs at once
// (no restart of the old build first, no grace, no wait for a round).
func TestObliReachPrivacyReleaseInstallsImmediately(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.kicked()
	h.afterSpread()
	h.underPrivacy(2 * time.Hour)
	expectState(t, h.m.Report(), orStatePrivacyDeferred, "")
	if h.ops.probe.Running || !h.ops.probe.StartDisabled || h.downloads() != 0 {
		t.Fatalf("under privacy: probe %+v downloads=%d", h.ops.probe, h.downloads())
	}
	r := h.release()
	expectState(t, r, orStateUpToDate, "")
	if h.downloads() != 1 || len(h.ops.installs) != 1 || h.ops.installs[0].uninstallFirst || h.ops.installs[0].version != "1.0.198" {
		t.Fatalf("downloads=%d installs=%+v", h.downloads(), h.ops.installs)
	}
	if h.ops.starts != 0 {
		t.Fatalf("the old build was started (starts=%d): the MSI starts the new one itself", h.ops.starts)
	}
	if !r.Running || r.InstalledVersion != "1.0.198" {
		t.Fatalf("report %+v", r)
	}
	if !h.kicked() {
		t.Fatalf("no round requested after the release")
	}
	// The next round confirms, nothing more to do.
	h.advance(time.Minute)
	expectState(t, h.run(), orStateUpToDate, "")
	if h.downloads() != 1 || h.ops.starts != 0 {
		t.Fatalf("acted again: downloads=%d starts=%d", h.downloads(), h.ops.starts)
	}
}

// Privacy mode shorter than any grace (agent just started): still immediate.
func TestObliReachPrivacyReleaseAfterShortPrivacy(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.advance(2 * time.Minute) // agent started 2 min ago (first round not even due)
	h.underPrivacy(time.Minute)
	r := h.release()
	expectState(t, r, orStateUpToDate, "")
	if len(h.ops.installs) != 1 || h.ops.starts != 0 {
		t.Fatalf("installs=%d starts=%d", len(h.ops.installs), h.ops.starts)
	}

	// Unix (no self-update, the manager launches it): same, launched once.
	h2 := newReachHarness(t, false)
	h2.ops.probe = h2.alignedProbe("1.0.197", true)
	h2.ops.probe.Hash = strings.Repeat("00", 32)
	h2.m.SetDesired(h2.desired())
	h2.underPrivacy(time.Minute)
	expectState(t, h2.release(), orStateUpToDate, "")
	if len(h2.ops.installs) != 1 || h2.ops.starts != 1 || !h2.ops.probe.Running {
		t.Fatalf("unix: installs=%d starts=%d probe=%+v", len(h2.ops.installs), h2.ops.starts, h2.ops.probe)
	}
}

// The install cannot complete → the installed (old) build is started: remote
// access is never lost; the failure is booked and visible.
func TestObliReachPrivacyReleaseFallbackStartsOld(t *testing.T) {
	// a) download refused by the server
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.underPrivacy(10 * time.Minute)
	h.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	r := h.release()
	expectState(t, r, orStateFailed, "")
	if r.Error != "http_500" || r.Attempts != 1 || len(h.ops.installs) != 0 {
		t.Fatalf("report %+v installs=%d", r, len(h.ops.installs))
	}
	if next, _ := time.Parse(time.RFC3339, r.NextAttemptAt); !next.Equal(h.now.Add(2 * time.Minute)) {
		t.Fatalf("backoff: next=%s", r.NextAttemptAt)
	}
	if h.ops.starts != 1 || !h.ops.probe.Running {
		t.Fatalf("old build not started after the failed install: starts=%d", h.ops.starts)
	}

	// b) msiexec fails
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.197", true)
	h2.ops.installErr = orErr("msi_exit_1603", "see install.log")
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	h2.underPrivacy(10 * time.Minute)
	r = h2.release()
	expectState(t, r, orStateFailed, "")
	if !strings.HasPrefix(r.Error, "msi_exit_1603") || len(h2.ops.installs) != 1 || h2.ops.starts != 1 {
		t.Fatalf("report %+v installs=%d starts=%d", r, len(h2.ops.installs), h2.ops.starts)
	}

	// c) installer busy after the download: short busy retry, old build started
	h3 := newReachHarness(t, true)
	h3.ops.probe = h3.alignedProbe("1.0.197", true)
	h3.ops.installErr = &orError{Busy: orReasonBusyMSI}
	h3.m.SetDesired(h3.desired())
	h3.afterSpread()
	h3.underPrivacy(10 * time.Minute)
	r = h3.release()
	expectState(t, r, orStatePending, orReasonBusyMSI)
	if r.Attempts != 0 || h3.ops.starts != 1 || !h3.m.st.NextBusyAt.Equal(h3.now.Add(time.Minute)) {
		t.Fatalf("report %+v starts=%d nextBusyAt=%s", r, h3.ops.starts, h3.m.st.NextBusyAt)
	}
}

// Installer busy (e.g. an MSI running) or a remote session held: the old build
// is started for now, nothing downloaded, and a round is requested.
func TestObliReachPrivacyReleaseBusyStartsOldAndKicks(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.underPrivacy(30 * time.Minute)
	h.kicked()
	h.ops.busy = orReasonBusyMSI
	h.release()
	if h.ops.starts != 1 || h.downloads() != 0 || len(h.ops.installs) != 0 {
		t.Fatalf("busy: starts=%d downloads=%d installs=%d", h.ops.starts, h.downloads(), len(h.ops.installs))
	}
	if !h.kicked() {
		t.Fatalf("no round requested")
	}
	expectState(t, h.run(), orStatePending, orReasonBusyMSI)

	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.197", true)
	d := h2.desired()
	d.Hold = true
	h2.m.SetDesired(d)
	h2.afterSpread()
	h2.underPrivacy(30 * time.Minute)
	h2.release()
	if h2.ops.starts != 1 || h2.downloads() != 0 {
		t.Fatalf("hold: starts=%d downloads=%d", h2.ops.starts, h2.downloads())
	}
}

// A backoff / busy retry booked before privacy mode does not delay the
// install after it (stale context).
func TestObliReachPrivacyReleaseClearsStaleBackoff(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.underPrivacy(5 * time.Minute)
	h.m.st.Attempts, h.m.st.NextAttemptAt, h.m.st.LastError = 3, h.now.Add(50*time.Minute), "msi_exit_1603"
	h.m.st.BusyRetries, h.m.st.NextBusyAt = 2, h.now.Add(30*time.Minute)
	r := h.release()
	expectState(t, r, orStateUpToDate, "")
	if len(h.ops.installs) != 1 || r.Attempts != 0 || h.m.st.BusyRetries != 0 || !h.m.st.NextBusyAt.IsZero() {
		t.Fatalf("installs=%d report=%+v st=%+v", len(h.ops.installs), r, h.m.st)
	}
}

// Up to date, stopped by privacy mode → started right away (no 5 min
// not-running grace); no target / disabled → the installed build is started
// as before; already running / privacy back on / not installed → untouched.
func TestObliReachPrivacyReleaseStartPaths(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.198", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.underPrivacy(10 * time.Minute)
	r := h.release()
	expectState(t, r, orStateUpToDate, "")
	if h.ops.starts != 1 || !r.Running || h.downloads() != 0 {
		t.Fatalf("aligned: starts=%d downloads=%d %+v", h.ops.starts, h.downloads(), r)
	}

	// No target from the server (older server / no push yet).
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.190", false)
	h2.m.PrivacyReleased()
	if h2.ops.starts != 1 || h2.downloads() != 0 {
		t.Fatalf("no target: starts=%d downloads=%d", h2.ops.starts, h2.downloads())
	}
	h2b := newReachHarness(t, true) // nothing installed: nothing to start
	h2b.m.PrivacyReleased()
	if h2b.ops.starts != 0 {
		t.Fatalf("started a missing ObliReach")
	}

	// Automatic install off: start what is there, never download.
	h3 := newReachHarness(t, true)
	h3.ops.probe = h3.alignedProbe("1.0.190", false)
	d := h3.desired()
	d.Enabled = false
	h3.m.SetDesired(d)
	h3.m.PrivacyReleased()
	if h3.ops.starts != 1 || h3.downloads() != 0 {
		t.Fatalf("disabled: starts=%d downloads=%d", h3.ops.starts, h3.downloads())
	}

	// Already running an older build (not stopped by privacy mode): the
	// regular rounds decide (self-update grace), nothing done here.
	h4 := newReachHarness(t, true)
	h4.ops.probe = h4.alignedProbe("1.0.197", true)
	h4.m.SetDesired(h4.desired())
	h4.m.PrivacyReleased()
	if h4.ops.starts != 0 || h4.downloads() != 0 {
		t.Fatalf("running: starts=%d downloads=%d", h4.ops.starts, h4.downloads())
	}

	// Privacy mode back on before the release ran.
	h5 := newReachHarness(t, true)
	h5.ops.probe = h5.alignedProbe("1.0.197", false)
	h5.m.SetDesired(h5.desired())
	h5.privacy = true
	h5.m.PrivacyReleased()
	if h5.ops.starts != 0 || h5.downloads() != 0 {
		t.Fatalf("privacy on: starts=%d downloads=%d", h5.ops.starts, h5.downloads())
	}

	// Not installed: the regular round (spread) installs it.
	h6 := newReachHarness(t, true)
	h6.m.SetDesired(h6.desired())
	h6.m.PrivacyReleased()
	if h6.ops.starts != 0 || h6.downloads() != 0 {
		t.Fatalf("missing: starts=%d downloads=%d", h6.ops.starts, h6.downloads())
	}
}

// Two releases queued behind a round: only the newest acts.
func TestObliReachPrivacyReleaseSuperseded(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", false)
	h.m.SetDesired(h.desired())
	// Every release that runs would install again: the install fails and the
	// old build cannot be started, so the probe stays "older, not running"
	// (a second, non-superseded release would find the same work to do).
	h.ops.installErr = orErr("msi_exit_1603", "see install.log")
	h.ops.startErr = orErr("start_failed", "access denied")
	h.m.opMu.Lock() // a round in progress
	var wg sync.WaitGroup
	for i := uint64(1); i <= 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.m.PrivacyReleased() }()
		for h.m.releaseGen.Load() != i {
			time.Sleep(time.Millisecond)
		}
	}
	h.m.opMu.Unlock()
	wg.Wait()
	if len(h.ops.installs) != 1 || h.downloads() != 1 {
		t.Fatalf("superseded release ran too: installs=%d downloads=%d", len(h.ops.installs), h.downloads())
	}
	// Control: a later release (not superseded) does run the pipeline again.
	h.m.PrivacyReleased()
	if len(h.ops.installs) != 2 {
		t.Fatalf("a non-superseded release must install: installs=%d", len(h.ops.installs))
	}
}

// The waiting_self_update grace counts from the first round that sees
// ObliReach RUNNING an older build, not from a mismatch stamped while it was
// stopped (privacy mode): it gets its 5 min, then the manager installs.
func TestObliReachSelfUpdateGraceCountsFromRunning(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.underPrivacy(2 * time.Hour) // MismatchSince 2 h ago
	h.privacy = false
	h.ops.probe.Running, h.ops.probe.StartDisabled = true, false // restarted by someone else
	r := h.run()
	expectState(t, r, orStatePending, orReasonSelfUpdate)
	if next, _ := time.Parse(time.RFC3339, r.NextAttemptAt); !next.Equal(h.now.Add(orSelfUpdateGrace)) {
		t.Fatalf("grace end not reported: %q", r.NextAttemptAt)
	}
	// ObliReach's own MSI run: service pending for a while — the clock keeps running.
	h.advance(2 * time.Minute)
	h.ops.probe.Running, h.ops.probe.Pending = false, true
	h.ops.busy = orReasonBusyMSI
	expectState(t, h.run(), orStatePending, orReasonBusyMSI)
	h.ops.probe.Running, h.ops.probe.Pending, h.ops.busy = true, false, "" // its update failed, old build back
	h.advance(2 * time.Minute)
	expectState(t, h.run(), orStatePending, orReasonSelfUpdate)
	if h.downloads() != 0 {
		t.Fatalf("fought ObliReach's self-update")
	}
	h.advance(time.Minute) // 5 min since it was first seen running
	expectState(t, h.run(), orStateUpToDate, "")
	if len(h.ops.installs) != 1 || h.ops.installs[0].uninstallFirst {
		t.Fatalf("installs %+v", h.ops.installs)
	}
	if !h.m.st.SelfUpdateSince.IsZero() {
		t.Fatalf("SelfUpdateSince not cleared once aligned")
	}

	// The clock is persisted (agent restart) and cleared when it stops.
	h2 := newReachHarness(t, true)
	h2.ops.probe = h2.alignedProbe("1.0.197", true)
	h2.m.SetDesired(h2.desired())
	h2.afterSpread()
	h2.run()
	since := h2.m.st.SelfUpdateSince
	m2 := newObliReachManager(h2.ops, h2.env, h2.statePath)
	m2.SetDesired(h2.desired())
	h2.advance(time.Minute)
	m2.Reconcile()
	if !m2.st.SelfUpdateSince.Equal(since) {
		t.Fatalf("SelfUpdateSince not persisted: %s vs %s", m2.st.SelfUpdateSince, since)
	}
	h2.ops.probe.Running = false
	m2.Reconcile()
	if !m2.st.SelfUpdateSince.IsZero() {
		t.Fatalf("SelfUpdateSince kept while ObliReach is stopped")
	}
}

func TestObliReachBusyRetryLadderShort(t *testing.T) {
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", false)
	h.ops.installErr = &orError{Busy: orReasonBusyMSI}
	h.m.SetDesired(h.desired())
	h.afterSpread()
	h.run()
	h.advance(orMismatchGrace)
	for i, step := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		r := h.run()
		expectState(t, r, orStatePending, orReasonBusyMSI)
		if !h.m.st.NextBusyAt.Equal(h.now.Add(step)) || h.m.st.BusyRetries != i+1 {
			t.Fatalf("busy retry %d: next=%s want now+%s", i+1, h.m.st.NextBusyAt, step)
		}
		if next, _ := time.Parse(time.RFC3339, r.NextAttemptAt); !next.Equal(h.m.st.NextBusyAt) {
			t.Fatalf("busy retry %d: reported next %q", i+1, r.NextAttemptAt)
		}
		hits := h.downloads()
		h.advance(step - time.Second)
		h.run()
		if h.downloads() != hits {
			t.Fatalf("downloaded before the busy retry time")
		}
		h.advance(time.Second)
	}
}

// A change of reason alone (same state) is logged and pushed.
func TestObliReachReasonChangeLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	h := newReachHarness(t, true)
	h.ops.probe = h.alignedProbe("1.0.197", true)
	h.m.SetDesired(h.desired())
	h.afterSpread()
	expectState(t, h.run(), orStatePending, orReasonSelfUpdate)
	pushes := h.notifies
	h.ops.busy = orReasonBusyMSI
	expectState(t, h.run(), orStatePending, orReasonBusyMSI)
	if !strings.Contains(buf.String(), `state pending (reason="busy_msi"`) {
		t.Fatalf("reason change not logged:\n%s", buf.String())
	}
	if h.notifies == pushes {
		t.Fatalf("reason change did not trigger a push")
	}
	n := strings.Count(buf.String(), `reason="busy_msi"`)
	h.run() // same reason again: not logged twice
	if strings.Count(buf.String(), `reason="busy_msi"`) != n {
		t.Fatalf("unchanged state logged again")
	}
}

// ── Pure helpers ────────────────────────────────────────────────────────────

func TestVerifyObliReachArtifact(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.bin")
	payload := []byte("hello oblireach")
	if err := os.WriteFile(p, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])
	noSig := func(string) error { return nil }

	if oe := verifyObliReachArtifact(p, int64(len(payload)), good, noSig); oe != nil {
		t.Fatalf("good file refused: %v", oe)
	}
	if oe := verifyObliReachArtifact(p, int64(len(payload)), strings.ToUpper(good), noSig); oe != nil {
		t.Fatalf("uppercase hash refused: %v", oe)
	}
	if oe := verifyObliReachArtifact(p, int64(len(payload))+1, good, noSig); oe == nil || oe.Code != "size_mismatch" {
		t.Fatalf("size: %v", oe)
	}
	if oe := verifyObliReachArtifact(p, int64(len(payload)), strings.Repeat("0", 64), noSig); oe == nil || oe.Code != "sha256_mismatch" {
		t.Fatalf("sha: %v", oe)
	}
	if oe := verifyObliReachArtifact(p, int64(len(payload)), "", noSig); oe == nil || oe.Code != "no_hash" {
		t.Fatalf("empty hash must be refused (never 'skip check'): %v", oe)
	}
	if oe := verifyObliReachArtifact(filepath.Join(dir, "missing"), 1, good, noSig); oe == nil {
		t.Fatalf("missing file accepted")
	}
	typed := func(string) error { return &orError{Code: "signature_untrusted_root", Detail: "x"} }
	if oe := verifyObliReachArtifact(p, int64(len(payload)), good, typed); oe == nil || oe.Code != "signature_untrusted_root" {
		t.Fatalf("typed signature error: %v", oe)
	}
	untyped := func(string) error { return errors.New("bad") }
	if oe := verifyObliReachArtifact(p, int64(len(payload)), good, untyped); oe == nil || oe.Code != "signature_invalid" {
		t.Fatalf("untyped signature error: %v", oe)
	}
	// The platform wrapper: hash-only outside Windows, Authenticode on
	// Windows (an unsigned file must be refused there).
	err := verifyObliReachSigner(p)
	if (err == nil) != (obliReachPlatformOps.Traits().alignByHash) {
		t.Fatalf("platform signature wrapper on an unsigned file: %v", err)
	}
}

func TestObliReachVersionCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.198", "1.0.198", 0},
		{"1.0.198", "1.0.198.0", 0},
		{"v1.0.198", "1.0.198", 0},
		{"1.0.197", "1.0.198", -1},
		{"1.0.200", "1.0.198", 1},
		{"1.1.0", "1.0.999", 1},
		{"", "1.0.0", -1},
		{"1.0.0", "", 1},
	}
	for _, c := range cases {
		if got := obliReachVersionCmp(c.a, c.b); got != c.want {
			t.Errorf("cmp(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestObliReachArtifactName(t *testing.T) {
	cases := map[[2]string]string{
		{"windows", "amd64"}: "oblireach-agent.msi",
		{"windows", "386"}:   "",
		{"windows", "arm64"}: "",
		{"darwin", "amd64"}:  "oblireach-agent-darwin-amd64",
		{"darwin", "arm64"}:  "oblireach-agent-darwin-arm64",
		{"linux", "amd64"}:   "oblireach-agent-linux-amd64",
		{"linux", "arm64"}:   "",
		{"freebsd", "amd64"}: "",
	}
	for k, want := range cases {
		if got := obliReachArtifactName(k[0], k[1]); got != want {
			t.Errorf("%s/%s: %q want %q", k[0], k[1], got, want)
		}
	}
}
