package main

// ── ObliReach auto-install / auto-update manager ─────────────────────────────
//
// The Obliance agent keeps the ObliReach agent (remote screen streaming)
// installed and aligned with the version the Obliance server ships
// (agent/dist/oblireach-version.txt on the server). No new command type and
// no new poll: the wanted version rides on the existing /api/agent/push
// response (`oblireach` block) and the agent reports what it did
// in the next push body (`oblireach` block).
//
// Rules enforced here (platform-independent, unit-tested with fake OS ops):
//   - artifacts come ONLY from the enrolled Obliance server: the URL is always
//     cfg.ServerURL + "/api/agent/download/" + <our own artifact name>, never a
//     URL sent by the server, redirects are refused (airgap-safe);
//   - the SHA-256 and size from the authenticated push are MANDATORY and are
//     re-checked on disk; on Windows the MSI must also carry a valid
//     Authenticode signature from the same signer as this agent (or the pinned
//     publisher) — see authenticode_windows.go;
//   - privacy mode wins: nothing is downloaded or installed while it is on,
//     it is re-checked right before and after the installer, and a separate
//     15 s loop stops ObliReach again if anything restarted it;
//   - no fight with ObliReach's own self-update (Windows): grace periods,
//     "busy" detection (MSI mutex, pending service, agent self-update) and a
//     `hold` flag while a remote session is active;
//   - failures back off exponentially (2/5/15/30/60 min, capped at 1 h,
//     persisted across agent restarts) and are reported with a stable code;
//     the ladder is cleared only once ObliReach has been seen running on a
//     later round, at least orConfirmRunning after the last start/install (a
//     "successful" start or repair that dies again keeps escalating);
//   - an installer found busy AFTER the download retries on a short ladder
//     (1/2/3/5/5 min, no failure counted: the contention is transient);
//   - privacy mode turned off (PrivacyReleased): ObliReach was stopped the
//     whole time and could not update itself, so a due update is installed
//     right away instead of restarting the old build (which would race its
//     own self-update against this manager); the installed build is started
//     whenever the install cannot run or fails — remote access is never lost.
//
// The manager never uninstalls ObliReach because auto-install was turned off
// (`enabled:false` only stops the management).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Contract types ──────────────────────────────────────────────────────────

// ObliReachDesired is the `oblireach` block of the push RESPONSE.
type ObliReachDesired struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Hold    bool   `json:"hold,omitempty"`
}

// ObliReachReport is the `oblireach` block of the push REQUEST.
type ObliReachReport struct {
	State            string `json:"state"`
	InstalledVersion string `json:"installedVersion"`
	DesiredVersion   string `json:"desiredVersion"`
	Running          bool   `json:"running"`
	Reason           string `json:"reason"`
	Error            string `json:"error"`
	Attempts         int    `json:"attempts"`
	NextAttemptAt    string `json:"nextAttemptAt"`
	LastAttemptAt    string `json:"lastAttemptAt"`
	Since            string `json:"since"`
}

const (
	orStateUpToDate        = "up_to_date"
	orStatePending         = "pending"
	orStateInstalling      = "installing"
	orStateFailed          = "failed"
	orStatePrivacyDeferred = "privacy_deferred"
	orStateDisabled        = "disabled"
	orStateUnsupported     = "unsupported"
)

// Pending / failed sub-reasons (A2 `reason`).
const (
	orReasonSelfUpdate   = "waiting_self_update"
	orReasonGrace        = "grace"
	orReasonSpread       = "spread"
	orReasonBusyMSI      = "busy_msi"
	orReasonBusyAgentUpd = "busy_agent_update"
	orReasonHold         = "hold"
	orReasonBackoff      = "backoff"
)

const (
	orMaxArtifactSize = 200 << 20
	orFirstRunDelay   = 90 * time.Second
	orPrivacyTick     = 15 * time.Second
	orReconcileEvery  = 60 * time.Second
	orMissingSpread   = 600 // seconds
	// A connected ObliReach gets `update` from the server within 30 s and a
	// healthy self-update completes in 1-2 min: counted from the first round
	// that saw it RUNNING an older build (SelfUpdateSince), not from the
	// first mismatch (which may date from privacy mode, when it could not
	// update itself).
	orSelfUpdateGrace   = 5 * time.Minute
	orMismatchGrace     = 3 * time.Minute
	orDownloadTimeout   = 10 * time.Minute
	orMaxStartFailures  = 3
	orConfirmRunning    = 10 * time.Minute // running this long after a start/install → backoff cleared
	orAgentUpdateQuiet  = 15 * time.Minute
	orMaxErrorLen       = 300
	obliReachStateFile  = "oblireach-manager.json"
	obliReachProcessTag = "oblireach-agent"
)

var orBackoffSteps = []time.Duration{
	2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, 60 * time.Minute,
}

// orBusyRetrySteps: installer found busy after the download (another MSI —
// typically ObliReach's own self-update — started meanwhile). Not a failure
// and transient: retry soon rather than an hour later.
var orBusyRetrySteps = []time.Duration{
	1 * time.Minute, 2 * time.Minute, 3 * time.Minute, 5 * time.Minute, 5 * time.Minute,
}

var (
	orVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	orSHA256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// msiMu serialises every msiexec this agent launches (its own MSI update in
// applyUpdateIfNewer and the ObliReach install/uninstall), so the two never
// race into ERROR_INSTALL_ALREADY_RUNNING (1618).
var msiMu sync.Mutex

// agentUpdateLaunchedAt is set (under updateMu) when this agent launched its
// own MSI update; ObliReach management stays "busy_agent_update" for a while
// so it does not start an msiexec while msiserver is replacing the agent.
var agentUpdateLaunchedAt time.Time

// agentSelfUpdateBusy reports whether this agent is downloading/applying its
// own update (update_agent) or launched one recently.
func agentSelfUpdateBusy() bool {
	updateMu.Lock()
	defer updateMu.Unlock()
	if updateInProgress {
		return true
	}
	return !agentUpdateLaunchedAt.IsZero() && time.Since(agentUpdateLaunchedAt) < orAgentUpdateQuiet
}

// obliReachArtifactName is the only file name this platform accepts from the
// manifest ("" = ObliReach is not shipped for this OS/arch). The ObliReach MSI
// is x64-only; the server ships no linux/arm64 nor FreeBSD build.
func obliReachArtifactName(goos, goarch string) string {
	switch goos {
	case "windows":
		if goarch == "amd64" {
			return "oblireach-agent.msi"
		}
	case "darwin":
		if goarch == "amd64" || goarch == "arm64" {
			return "oblireach-agent-darwin-" + goarch
		}
	case "linux":
		if goarch == "amd64" {
			return "oblireach-agent-linux-amd64"
		}
	}
	return ""
}

// ObliReach build for Windows 7 SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2
// (Windows NT 6.x): the ObliReach agent built with Go 1.20, a separate MSI
// (same UpgradeCode / service) because a Go >= 1.21 binary does not start
// there (the modern MSI's service fails: error 1920 → 1603).
const obliReachArtifactNT6 = "oblireach-agent-nt6.msi"

// obliReachWindowsArtifact picks the Windows artifact by OS major version
// (RtlGetVersion: 10 = Windows 10 / 11 / Server 2016+, 6 = NT 6.x).
func obliReachWindowsArtifact(goarch string, osMajor uint32) string {
	if goarch != "amd64" {
		return ""
	}
	if osMajor != 0 && osMajor < 10 {
		return obliReachArtifactNT6
	}
	return "oblireach-agent.msi"
}

// obliReachNT6Mismatch explains why a manifest file cannot be used on an
// NT 6.x Windows: the server (older, or shipping no nt6 build) offers no
// usable ObliReach for this OS → "unsupported" (never retried), not
// "bad_manifest" (a failure). "" when the file is not that case.
func obliReachNT6Mismatch(ours, file string, osMajor, osMinor, build uint32) string {
	if ours != obliReachArtifactNT6 || file == ours {
		return ""
	}
	if file == "" || file == "oblireach-agent.msi" {
		return fmt.Sprintf("os_too_old: the server ships no ObliReach build for this Windows version (%d.%d build %d): %s is required, %s needs Windows 10 / Server 2016 or later",
			osMajor, osMinor, build, obliReachArtifactNT6, "oblireach-agent.msi")
	}
	return ""
}

// obliReachFileRejecter is optionally implemented by the platform ops: a
// manifest file that is not ours but is a known "not for this OS" case gets
// an "unsupported" state with this message instead of "bad_manifest".
type obliReachFileRejecter interface {
	RejectFile(ours, file string) string
}

// ── OS abstraction (real: oblireach_manager_{windows,unix}.go; tests: fakes) ─

type obliReachServer struct {
	URL    string
	APIKey string
}

// obliReachProbe is a snapshot of the installed ObliReach.
type obliReachProbe struct {
	Installed     bool   // Windows: MSI product registered; Unix: binary present
	ProductCode   string // Windows MSI ProductCode
	Version       string // installed version ("" = unknown)
	Hash          string // Unix: SHA-256 of the installed binary
	ServiceExists bool   // Windows: OblireachAgent service registered; Unix: = Installed
	Running       bool
	Pending       bool // Windows: service in a *_PENDING state
	StartDisabled bool // Windows: service start type = disabled
}

type obliReachTraits struct {
	alignByHash       bool          // Unix: aligned when binary SHA-256 == target
	selfUpdates       bool          // Windows: ObliReach updates itself (grace orSelfUpdateGrace while it runs)
	startAfterInstall bool          // Unix: the manager launches it; the MSI starts the service itself
	notRunningGrace   time.Duration // aligned but not running → start after this
}

// obliReachStage is where one artifact is downloaded before install.
type obliReachStage struct {
	Dir  string
	Path string
}

type obliReachOps interface {
	Traits() obliReachTraits
	ArtifactName() string
	// Precondition returns "" when ObliReach can run here, else "<code>: <detail>".
	// strict=false (manual install) skips checks an admin may knowingly override.
	Precondition(strict bool) string
	Probe(want *ObliReachDesired, deep bool) obliReachProbe
	// Busy returns a pending reason ("busy_msi") while an installer is running.
	Busy(p obliReachProbe) string
	Stage(file string) (obliReachStage, error)
	FinishStage(s obliReachStage, keepLogs bool)
	DiscardStaging(dir string)
	VerifySignature(path string) error
	Install(path string, want *ObliReachDesired, p obliReachProbe, uninstallFirst bool, srv obliReachServer) error
	Start(srv obliReachServer) error
	Stop()
	// EnforceStopped stops + disables ObliReach if it runs or may auto-start;
	// returns true when it had to act.
	EnforceStopped(deep bool) bool
}

// obliReachEnv groups every non-OS dependency so tests can drive the clock,
// privacy mode and the network.
type obliReachEnv struct {
	now        func() time.Time
	privacy    func() bool
	agentBusy  func() bool
	server     func() obliReachServer
	deviceUUID func() string
	notify     func()
	jitter     func() float64 // uniform in [-1, 1]
	client     *http.Client
}

// ── Errors ──────────────────────────────────────────────────────────────────

// orError is a classified failure. Busy/Privacy are NOT failures: they turn
// into pending / privacy_deferred without touching the backoff.
type orError struct {
	Code           string
	Detail         string
	Busy           string
	Privacy        bool
	ForceUninstall bool
}

func (e *orError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func orErr(code, format string, args ...interface{}) *orError {
	return &orError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// asOrError converts any error into an *orError (defaultCode when untyped).
func asOrError(err error, defaultCode string) *orError {
	if err == nil {
		return nil
	}
	var oe *orError
	if errors.As(err, &oe) {
		return oe
	}
	return &orError{Code: defaultCode, Detail: err.Error()}
}

func shortHash(h string) string { return truncateStr(h, 12) }

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ── Persisted state ─────────────────────────────────────────────────────────

type obliReachPersist struct {
	DesiredVersion string    `json:"desiredVersion,omitempty"`
	DesiredSHA256  string    `json:"desiredSha256,omitempty"`
	Attempts       int       `json:"attempts,omitempty"`
	NextAttemptAt  time.Time `json:"nextAttemptAt,omitempty"`
	LastAttemptAt  time.Time `json:"lastAttemptAt,omitempty"`
	LastError      string    `json:"lastError,omitempty"`
	MismatchSince  time.Time `json:"mismatchSince,omitempty"`
	StartFailures  int       `json:"startFailures,omitempty"`
	Repair         bool      `json:"repair,omitempty"`
	ForceUninstall bool      `json:"forceUninstall,omitempty"`
	StagingDir     string    `json:"stagingDir,omitempty"`
	State          string    `json:"state,omitempty"`
	Since          time.Time `json:"since,omitempty"`
	// ConfirmSince: last start/install that succeeded but has not yet been
	// confirmed by ObliReach still running orConfirmRunning later.
	ConfirmSince time.Time `json:"confirmSince,omitempty"`
	// Installer found busy after the download: retry on orBusyRetrySteps
	// (not a failure) instead of downloading again every round.
	BusyRetries int       `json:"busyRetries,omitempty"`
	NextBusyAt  time.Time `json:"nextBusyAt,omitempty"`
	BusyReason  string    `json:"busyReason,omitempty"`
	// SelfUpdateSince: first round that saw ObliReach RUNNING an older build
	// (it can update itself from then on); the waiting_self_update grace is
	// counted from here. Cleared when it stops running, is aligned, or under
	// privacy mode.
	SelfUpdateSince time.Time `json:"selfUpdateSince,omitempty"`
}

// ── Manager ─────────────────────────────────────────────────────────────────

type obliReachManager struct {
	ops       obliReachOps
	env       obliReachEnv
	statePath string // "" = configDir/oblireach-manager.json

	// opMu serialises reconcile and manual installs; st is only touched
	// while holding it.
	opMu            sync.Mutex
	st              obliReachPersist
	loaded          bool
	lastSaved       []byte
	notRunningSince time.Time

	mu         sync.Mutex // guards desired, report, agentStart
	desired    *ObliReachDesired
	report     *ObliReachReport
	agentStart time.Time
	started    bool

	kickCh chan struct{}
	// releaseGen: generation of the last privacy release (a newer one
	// supersedes a release still waiting for opMu).
	releaseGen atomic.Uint64
}

// obliReachCfg is the agent config the real env reads (set by Start).
var obliReachCfg atomic.Pointer[Config]

func defaultObliReachEnv() obliReachEnv {
	return obliReachEnv{
		now:       time.Now,
		privacy:   IsPrivacyMode,
		agentBusy: agentSelfUpdateBusy,
		server: func() obliReachServer {
			c := obliReachCfg.Load()
			if c == nil {
				return obliReachServer{}
			}
			return obliReachServer{URL: c.ServerURL, APIKey: c.APIKey}
		},
		deviceUUID: func() string {
			if c := obliReachCfg.Load(); c != nil {
				return currentDeviceUUID()
			}
			return ""
		},
		notify: TriggerImmediatePush,
		jitter: func() float64 { return mathrand.Float64()*2 - 1 },
		client: &http.Client{
			Timeout: orDownloadTimeout,
			// Artifacts come from the enrolled server only: never follow a
			// redirect to somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func newObliReachManager(ops obliReachOps, env obliReachEnv, statePath string) *obliReachManager {
	return &obliReachManager{
		ops:        ops,
		env:        env,
		statePath:  statePath,
		agentStart: env.now(),
		kickCh:     make(chan struct{}, 1),
	}
}

// obliReachMgr is the process-wide manager (push.go feeds it the target and
// reads its report; install_oblireach.go uses InstallNow).
var obliReachMgr = newObliReachManager(obliReachPlatformOps, defaultObliReachEnv(), "")

// Start launches the manager loops. Idempotent.
func (m *obliReachManager) Start(cfg *Config) {
	obliReachCfg.Store(cfg)
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.agentStart = m.env.now()
	m.mu.Unlock()

	go m.privacyLoop()
	go m.reconcileLoop()
}

// SetDesired stores the target received in a push response (nil = the server
// sent no block → the manager idles and reports nothing).
func (m *obliReachManager) SetDesired(d *ObliReachDesired) {
	var cp *ObliReachDesired
	if d != nil {
		c := *d
		c.Version = strings.TrimSpace(c.Version)
		c.File = strings.TrimSpace(c.File)
		c.SHA256 = strings.ToLower(strings.TrimSpace(c.SHA256))
		cp = &c
	}
	m.mu.Lock()
	changed := !desiredEqual(m.desired, cp)
	m.desired = cp
	if cp == nil {
		m.report = nil
	}
	m.mu.Unlock()
	if changed {
		m.Kick()
	}
}

// Kick asks the reconcile loop for a round now instead of at its next 60 s
// tick (non-blocking; a kick before the first round is remembered).
func (m *obliReachManager) Kick() {
	select {
	case m.kickCh <- struct{}{}:
	default:
	}
}

func desiredEqual(a, b *ObliReachDesired) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (m *obliReachManager) getDesired() *ObliReachDesired {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.desired == nil {
		return nil
	}
	c := *m.desired
	return &c
}

// Report returns the last computed status for the push body, or nil before
// the manager has run / when the server sent no target.
func (m *obliReachManager) Report() *ObliReachReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.desired == nil || m.report == nil {
		return nil
	}
	c := *m.report
	return &c
}

func (m *obliReachManager) privacyLoop() {
	t := time.NewTicker(orPrivacyTick)
	defer t.Stop()
	n := 0
	for range t.C {
		n++
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("oblireach: PANIC in privacy check: %v", r)
				}
			}()
			// Cheap check every 15 s; a full process scan (Unix) once a minute.
			m.PrivacyTick(n%4 == 0)
		}()
	}
}

func (m *obliReachManager) reconcileLoop() {
	t := time.NewTicker(orPrivacyTick)
	defer t.Stop()
	var last time.Time
	kicked := false
	for {
		select {
		case <-t.C:
		case <-m.kickCh:
			kicked = true
		}
		m.mu.Lock()
		start := m.agentStart
		m.mu.Unlock()
		if time.Since(start) < orFirstRunDelay {
			continue // kicks are remembered until the first run
		}
		if !kicked && !last.IsZero() && time.Since(last) < orReconcileEvery-time.Second {
			continue
		}
		kicked = false
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("oblireach: PANIC in reconcile: %v", r)
				}
			}()
			m.Reconcile()
		}()
		last = time.Now()
	}
}

// PrivacyTick is the privacy invariant: while privacy mode is on, ObliReach
// must not run nor be able to auto-start — whatever restarted it (an MSI
// finishing, ObliReach's own self-update, a user).
func (m *obliReachManager) PrivacyTick(deep bool) {
	if !m.env.privacy() {
		return
	}
	if m.ops.EnforceStopped(deep) {
		log.Printf("oblireach: privacy mode is on — ObliReach was running or enabled, stopped it again")
	}
}

// ── Persisted state helpers (callers hold opMu) ─────────────────────────────

func (m *obliReachManager) stateFile() string {
	if m.statePath != "" {
		return m.statePath
	}
	return filepath.Join(configDir, obliReachStateFile)
}

func (m *obliReachManager) ensureLoaded() {
	if m.loaded {
		return
	}
	m.loaded = true
	data, err := os.ReadFile(m.stateFile())
	if err != nil {
		return
	}
	var st obliReachPersist
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("oblireach: ignoring unreadable %s: %v", m.stateFile(), err)
		return
	}
	m.st = st
	m.lastSaved = data
}

func (m *obliReachManager) saveState() {
	data, err := json.MarshalIndent(m.st, "", "  ")
	if err != nil || string(data) == string(m.lastSaved) {
		return
	}
	path := m.stateFile()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("oblireach: could not save %s: %v", path, err)
		return
	}
	m.lastSaved = data
}

// syncTarget resets the backoff and the grace timers when the target
// (version, sha256) changes — a new build deserves a fresh try.
func (m *obliReachManager) syncTarget(want *ObliReachDesired) {
	if m.st.DesiredVersion == want.Version && m.st.DesiredSHA256 == want.SHA256 {
		return
	}
	if m.st.DesiredVersion != "" || m.st.DesiredSHA256 != "" {
		log.Printf("oblireach: target changed %s → %s — backoff reset", m.st.DesiredVersion, want.Version)
	}
	m.st.DesiredVersion = want.Version
	m.st.DesiredSHA256 = want.SHA256
	m.resetFailures()
	m.st.MismatchSince = time.Time{}
	m.st.SelfUpdateSince = time.Time{}
	m.st.Repair = false
}

func (m *obliReachManager) resetFailures() {
	m.st.Attempts = 0
	m.st.NextAttemptAt = time.Time{}
	m.st.LastError = ""
	m.st.StartFailures = 0
	m.st.ConfirmSince = time.Time{}
	m.clearBusyRetry()
}

func (m *obliReachManager) clearBusyRetry() {
	m.st.BusyRetries = 0
	m.st.NextBusyAt = time.Time{}
	m.st.BusyReason = ""
}

// recordStartFailure books a failed (or short-lived) start: backoff + after
// orMaxStartFailures in a row, the next attempt reinstalls.
func (m *obliReachManager) recordStartFailure(e *orError, now time.Time) {
	m.recordFailure(e, now)
	m.st.StartFailures++
	if m.st.StartFailures >= orMaxStartFailures {
		log.Printf("oblireach: %d start failures in a row — next attempt reinstalls", m.st.StartFailures)
		m.st.Repair = true
	}
}

// awaitConfirmation marks a start/install that just succeeded: the backoff is
// cleared only if ObliReach is still running orConfirmRunning later (never
// armed under privacy mode, where stopped is the expected state).
func (m *obliReachManager) awaitConfirmation(now time.Time) {
	if m.env.privacy() {
		m.st.ConfirmSince = time.Time{}
		return
	}
	m.st.ConfirmSince = now
}

func (m *obliReachManager) backoffDelay(attempts int) time.Duration {
	return m.ladderDelay(orBackoffSteps, attempts)
}

// ladderDelay: step `n` (1-based, capped at the last step) of a ladder, with
// ±10 % jitter.
func (m *obliReachManager) ladderDelay(steps []time.Duration, n int) time.Duration {
	idx := n - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(steps) {
		idx = len(steps) - 1
	}
	d := steps[idx]
	j := 0.0
	if m.env.jitter != nil {
		j = m.env.jitter()
	}
	if j > 1 {
		j = 1
	} else if j < -1 {
		j = -1
	}
	return d + time.Duration(float64(d)*0.1*j)
}

func (m *obliReachManager) recordFailure(e *orError, now time.Time) {
	m.st.Attempts++
	m.st.NextAttemptAt = now.Add(m.backoffDelay(m.st.Attempts))
	m.st.LastError = truncateStr(e.Error(), orMaxErrorLen)
	if e.ForceUninstall {
		m.st.ForceUninstall = true
	}
	log.Printf("oblireach: attempt %d failed: %s (next attempt at %s)",
		m.st.Attempts, m.st.LastError, m.st.NextAttemptAt.Format(time.RFC3339))
}

func (m *obliReachManager) inBackoff(now time.Time) bool {
	return m.st.Attempts > 0 && now.Before(m.st.NextAttemptAt)
}

// setState publishes a new report; a change of state, reason or error is
// logged and triggers an immediate push so the UI follows within seconds.
func (m *obliReachManager) setState(state, reason, errStr string, p *obliReachProbe, want *ObliReachDesired, now time.Time) {
	m.setStateNext(state, reason, errStr, p, want, now, time.Time{})
}

// setStateNext is setState with the time of the next attempt of a pending
// state (end of a grace, busy retry) reported as nextAttemptAt; zero = the
// failure backoff's, if any.
func (m *obliReachManager) setStateNext(state, reason, errStr string, p *obliReachProbe, want *ObliReachDesired, now, next time.Time) {
	if m.st.State != state || m.st.Since.IsZero() {
		m.st.State = state
		m.st.Since = now
	}
	r := &ObliReachReport{
		State:    state,
		Reason:   reason,
		Error:    truncateStr(errStr, orMaxErrorLen),
		Attempts: m.st.Attempts,
		Since:    m.st.Since.UTC().Format(time.RFC3339),
	}
	if want != nil {
		r.DesiredVersion = want.Version
	}
	if p != nil {
		r.InstalledVersion = p.Version
		r.Running = p.Running
	}
	if !next.IsZero() {
		r.NextAttemptAt = next.UTC().Format(time.RFC3339)
	} else if m.st.Attempts > 0 && now.Before(m.st.NextAttemptAt) {
		// The failure backoff's end, only while it is still ahead (a busy /
		// hold state after the backoff ended must not show a past time).
		r.NextAttemptAt = m.st.NextAttemptAt.UTC().Format(time.RFC3339)
	}
	if !m.st.LastAttemptAt.IsZero() {
		r.LastAttemptAt = m.st.LastAttemptAt.UTC().Format(time.RFC3339)
	}
	m.saveState()

	m.mu.Lock()
	prev := m.report
	m.report = r
	m.mu.Unlock()
	if prev == nil || prev.State != r.State || prev.Reason != r.Reason || prev.Error != r.Error {
		if prev == nil || prev.State != r.State || prev.Reason != r.Reason {
			// The reason too (waiting_self_update → busy_msi …): the log must
			// tell why an update is still not there.
			next := ""
			if r.NextAttemptAt != "" {
				next = " next=" + r.NextAttemptAt
			}
			log.Printf("oblireach: state %s (reason=%q installed=%q desired=%q running=%v error=%q%s)",
				r.State, r.Reason, r.InstalledVersion, r.DesiredVersion, r.Running, r.Error, next)
		}
		if m.env.notify != nil {
			m.env.notify()
		}
	}
}

func (m *obliReachManager) clearReport() {
	m.mu.Lock()
	m.report = nil
	m.mu.Unlock()
}

// ── Decisions ───────────────────────────────────────────────────────────────

// validateManifest checks the A1 block against this platform. It returns
// (state, error string) when the manifest cannot be acted upon.
func (m *obliReachManager) validateManifest(want *ObliReachDesired) (string, string) {
	ours := m.ops.ArtifactName()
	if ours == "" {
		return orStateUnsupported, "platform: ObliReach is not available for this OS/architecture"
	}
	if want.File != ours {
		if r, ok := m.ops.(obliReachFileRejecter); ok {
			if msg := r.RejectFile(ours, want.File); msg != "" {
				return orStateUnsupported, msg
			}
		}
	}
	if want.File == "" {
		return orStateUnsupported, "no_artifact: the server ships no ObliReach build for this OS/architecture"
	}
	if want.File != ours {
		return orStateFailed, fmt.Sprintf("bad_manifest: file %q does not match this platform (%q)", truncateStr(want.File, 80), ours)
	}
	if !orVersionRe.MatchString(want.Version) {
		return orStateFailed, fmt.Sprintf("bad_manifest: invalid version %q", truncateStr(want.Version, 40))
	}
	if !orSHA256Re.MatchString(want.SHA256) {
		return orStateFailed, "bad_manifest: invalid sha256"
	}
	if want.Size <= 0 || want.Size > orMaxArtifactSize {
		return orStateFailed, fmt.Sprintf("bad_manifest: invalid size %d", want.Size)
	}
	return "", ""
}

// obliReachVersionCmp compares dotted numeric versions ("1.0.198" vs
// "1.0.198.0" → equal). An empty/unknown version sorts first.
func obliReachVersionCmp(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// aligned: Windows → MSI product registered at the target version with its
// service; Unix → the installed binary hashes to the target SHA-256. An empty
// target version/hash (manual install without manifest) skips that part.
func (m *obliReachManager) aligned(p obliReachProbe, want *ObliReachDesired) bool {
	if !p.Installed {
		return false
	}
	if m.ops.Traits().alignByHash {
		return p.Hash != "" && (want.SHA256 == "" || p.Hash == want.SHA256)
	}
	return p.ServiceExists && (want.Version == "" || obliReachVersionCmp(p.Version, want.Version) == 0)
}

func (m *obliReachManager) busy(p obliReachProbe) string {
	if m.env.agentBusy != nil && m.env.agentBusy() {
		return orReasonBusyAgentUpd
	}
	return m.ops.Busy(p)
}

func (m *obliReachManager) spread() time.Duration {
	uuid := ""
	if m.env.deviceUUID != nil {
		uuid = m.env.deviceUUID()
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(uuid))
	return time.Duration(h.Sum32()%orMissingSpread) * time.Second
}

// quickProbe reports what is installed without acting (nil where ObliReach
// does not exist for this platform).
func (m *obliReachManager) quickProbe(want *ObliReachDesired) *obliReachProbe {
	if m.ops.ArtifactName() == "" {
		return nil
	}
	p := m.ops.Probe(want, false)
	return &p
}

// Reconcile runs one decision round (every 60 s, or right after the target
// changed).
func (m *obliReachManager) Reconcile() {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.reconcileLocked()
}

func (m *obliReachManager) reconcileLocked() {
	now := m.env.now()
	privacy := m.env.privacy()

	// 0. Privacy invariant — always, even when management is disabled.
	if privacy {
		m.ops.EnforceStopped(true)
	}

	want := m.getDesired()
	if want == nil {
		m.clearReport() // older server / no block: idle, no report
		return
	}
	m.ensureLoaded()
	m.syncTarget(want)

	// 1. Enabled check.
	if !want.Enabled {
		m.setState(orStateDisabled, "", "", m.quickProbe(want), want, now)
		return
	}

	// 2. Platform / manifest check.
	if state, msg := m.validateManifest(want); state != "" {
		m.setState(state, "", msg, m.quickProbe(want), want, now)
		return
	}
	if msg := m.ops.Precondition(true); msg != "" {
		m.setState(orStateUnsupported, "", msg, m.quickProbe(want), want, now)
		return
	}

	// 3. Probe + alignment.
	p := m.ops.Probe(want, true)
	traits := m.ops.Traits()
	if m.aligned(p, want) && !m.st.Repair {
		m.handleAligned(p, want, privacy, now)
		return
	}
	m.notRunningSince = time.Time{}
	m.st.ConfirmSince = time.Time{}

	// 4. Not aligned.
	if m.st.MismatchSince.IsZero() {
		m.st.MismatchSince = now
	}
	if privacy {
		// Stopped: it cannot update itself — no self-update clock runs.
		m.st.SelfUpdateSince = time.Time{}
		m.setState(orStatePrivacyDeferred, "", "", &p, want, now)
		return
	}
	// ObliReach (Windows) updates itself while it RUNS an older build: its
	// grace starts at the first round that sees it so (kept across the
	// pending states of its own MSI run, cleared once it no longer runs).
	selfUpdating := traits.selfUpdates && p.Running && obliReachVersionCmp(p.Version, want.Version) < 0
	if selfUpdating {
		if m.st.SelfUpdateSince.IsZero() {
			m.st.SelfUpdateSince = now
		}
	} else if !p.Pending {
		m.st.SelfUpdateSince = time.Time{}
	}
	if m.inBackoff(now) {
		m.setState(orStateFailed, orReasonBackoff, m.st.LastError, &p, want, now)
		return
	}
	if b := m.busy(p); b != "" {
		m.setState(orStatePending, b, "", &p, want, now)
		return
	}
	if now.Before(m.st.NextBusyAt) {
		// The last download ended on a busy installer: wait (no new download).
		reason := m.st.BusyReason
		if reason == "" {
			reason = orReasonBusyMSI
		}
		m.setStateNext(orStatePending, reason, "", &p, want, now, m.st.NextBusyAt)
		return
	}
	present := p.Installed || p.ServiceExists
	if want.Hold && present {
		m.setState(orStatePending, orReasonHold, "", &p, want, now)
		return
	}
	if !present {
		m.mu.Lock()
		start := m.agentStart
		m.mu.Unlock()
		if at := start.Add(m.spread()); now.Before(at) {
			m.setStateNext(orStatePending, orReasonSpread, "", &p, want, now, at)
			return
		}
	} else if !m.st.Repair {
		since, grace, reason := m.st.MismatchSince, orMismatchGrace, orReasonGrace
		if selfUpdating {
			since, grace, reason = m.st.SelfUpdateSince, orSelfUpdateGrace, orReasonSelfUpdate
		}
		if at := since.Add(grace); now.Before(at) {
			m.setStateNext(orStatePending, reason, "", &p, want, now, at)
			return
		}
	}

	_ = m.attemptInstall(want, p, m.upgradeNeedsUninstall(p, want), m.env.server())
}

// upgradeNeedsUninstall is the rule of an UPDATE (automatic rounds, privacy
// release, the "Update Reach" button): a plain `msiexec /i` (MajorUpgrade —
// Windows Installer rolls back to the installed build when it fails); the
// product is removed first only for a repair / forced reinstall, a broken
// registration (product without its service) or a downgrade.
func (m *obliReachManager) upgradeNeedsUninstall(p obliReachProbe, want *ObliReachDesired) bool {
	return m.st.ForceUninstall || m.st.Repair ||
		(p.Installed && !p.ServiceExists) ||
		(p.Installed && want.Version != "" && obliReachVersionCmp(p.Version, want.Version) > 0)
}

// handleAligned: the right version is installed; make sure it runs (unless
// privacy mode is on — then stopped is the expected state).
func (m *obliReachManager) handleAligned(p obliReachProbe, want *ObliReachDesired, privacy bool, now time.Time) {
	m.st.MismatchSince = time.Time{}
	m.st.SelfUpdateSince = time.Time{}
	m.clearBusyRetry() // nothing left to install
	if privacy {
		m.notRunningSince = time.Time{}
		m.st.ConfirmSince = time.Time{} // stopped is expected under privacy
		p.Running = false
		m.setState(orStateUpToDate, "", "", &p, want, now)
		return
	}
	if p.Running {
		m.notRunningSince = time.Time{}
		// Clear the backoff only once ObliReach has stayed up long enough
		// after the last start/install (a crash-at-start build must not reset
		// the ladder on every "successful" start or repair).
		confirmed := m.st.ConfirmSince.IsZero() || now.Sub(m.st.ConfirmSince) >= orConfirmRunning
		if confirmed && (m.st.Attempts > 0 || m.st.StartFailures > 0 || m.st.ForceUninstall || !m.st.ConfirmSince.IsZero()) {
			m.resetFailures()
			m.st.ForceUninstall = false
		}
		m.setState(orStateUpToDate, "", "", &p, want, now)
		return
	}
	if !m.st.ConfirmSince.IsZero() && !p.Pending {
		// Started (or installed) by us, then stopped again before being
		// confirmed: count it as a failed start so the backoff escalates.
		up := now.Sub(m.st.ConfirmSince).Round(time.Second)
		m.st.ConfirmSince = time.Time{}
		m.notRunningSince = now
		m.recordStartFailure(orErr("exited_after_start", "ObliReach stopped again within %s of its last start", up), now)
		m.setState(orStateFailed, "", m.st.LastError, &p, want, now)
		return
	}
	if m.notRunningSince.IsZero() {
		m.notRunningSince = now
	}
	if now.Sub(m.notRunningSince) < m.ops.Traits().notRunningGrace {
		m.setState(orStateUpToDate, "", "", &p, want, now)
		return
	}
	if m.inBackoff(now) {
		m.setState(orStateFailed, orReasonBackoff, m.st.LastError, &p, want, now)
		return
	}
	if b := m.busy(p); b != "" {
		m.setState(orStatePending, b, "", &p, want, now)
		return
	}
	log.Printf("oblireach: installed %s but not running — starting it", p.Version)
	m.st.LastAttemptAt = now
	if err := m.ops.Start(m.env.server()); err != nil {
		m.recordStartFailure(asOrError(err, "start_failed"), now)
		m.setState(orStateFailed, "", m.st.LastError, &p, want, now)
		return
	}
	// Not a reset: the ladder is cleared only when a later round confirms it
	// is still running (see the p.Running branch above).
	m.notRunningSince = time.Time{}
	m.awaitConfirmation(now)
	p2 := m.ops.Probe(want, true)
	m.setState(orStateUpToDate, "", "", &p2, want, m.env.now())
}

// attemptInstall runs the verified pipeline and books the outcome.
func (m *obliReachManager) attemptInstall(want *ObliReachDesired, p obliReachProbe, uninstallFirst bool, srv obliReachServer) *orError {
	now := m.env.now()
	m.st.LastAttemptAt = now
	m.setState(orStateInstalling, "", "", &p, want, now)
	log.Printf("oblireach: installing %s (installed=%q uninstallFirst=%v)", want.Version, p.Version, uninstallFirst)

	oe := m.installPipeline(want, p, uninstallFirst, srv)
	now = m.env.now()
	switch {
	case oe == nil:
		// Not resetFailures(): Attempts/NextAttemptAt keep escalating until a
		// later round sees ObliReach still running (a repair of a build that
		// crashes right after start must not restart the ladder at 2 min).
		m.st.LastError = ""
		m.st.StartFailures = 0
		m.clearBusyRetry()
		m.st.Repair = false
		m.st.ForceUninstall = false
		m.st.MismatchSince = time.Time{}
		m.st.SelfUpdateSince = time.Time{}
		m.notRunningSince = time.Time{}
		m.awaitConfirmation(now)
		p2 := m.ops.Probe(want, true)
		m.setState(orStateUpToDate, "", "", &p2, want, now)
		log.Printf("oblireach: ObliReach %s installed", p2.Version)
	case oe.Privacy:
		m.setState(orStatePrivacyDeferred, "", "", &p, want, now)
	case oe.Busy != "":
		// Busy is only detected here AFTER the download (the pre-download
		// check is in reconcileLocked): retry on the short busy ladder
		// (1/2/3/5/5 min) without counting a failure — the contention (most
		// often ObliReach's own msiexec) is transient, and the round does not
		// download again before that time.
		m.st.BusyRetries++
		m.st.NextBusyAt = now.Add(m.ladderDelay(orBusyRetrySteps, m.st.BusyRetries))
		m.st.BusyReason = oe.Busy
		log.Printf("oblireach: installer busy (%s) after the download — retry %d at %s",
			oe.Busy, m.st.BusyRetries, m.st.NextBusyAt.Format(time.RFC3339))
		m.setStateNext(orStatePending, oe.Busy, "", &p, want, now, m.st.NextBusyAt)
	default:
		m.recordFailure(oe, now)
		m.setState(orStateFailed, "", m.st.LastError, &p, want, now)
	}
	return oe
}

// installPipeline: stage → download → verify (size + SHA-256 + signature) →
// privacy/busy re-check → install → privacy enforcement → post-check.
func (m *obliReachManager) installPipeline(want *ObliReachDesired, p obliReachProbe, uninstallFirst bool, srv obliReachServer) (res *orError) {
	if srv.URL == "" {
		return orErr("download_failed", "no server URL configured")
	}
	if m.st.StagingDir != "" {
		m.ops.DiscardStaging(m.st.StagingDir)
		m.st.StagingDir = ""
	}
	stage, err := m.ops.Stage(want.File)
	if err != nil {
		return orErr("download_failed", "staging: %v", err)
	}
	defer func() {
		keep := res != nil && !res.Privacy && res.Busy == ""
		m.ops.FinishStage(stage, keep)
		if keep {
			m.st.StagingDir = stage.Dir // installer logs kept for diagnosis
		}
	}()

	sha, oe := m.download(srv, want.File, stage.Path, want.Size, want.SHA256)
	if oe != nil {
		return oe
	}
	eff := *want
	eff.SHA256 = sha
	if oe := verifyObliReachArtifact(stage.Path, want.Size, sha, m.ops.VerifySignature); oe != nil {
		return oe
	}
	if m.env.privacy() {
		return &orError{Privacy: true}
	}
	if b := m.busy(p); b != "" {
		return &orError{Busy: b}
	}
	if err := m.ops.Install(stage.Path, &eff, p, uninstallFirst, srv); err != nil {
		return asOrError(err, "install_failed")
	}
	if m.env.privacy() {
		// Privacy mode went on while installing: the MSI (re)started the
		// service — stop + disable it right now.
		m.ops.Stop()
	} else if m.ops.Traits().startAfterInstall {
		if err := m.ops.Start(srv); err != nil {
			return asOrError(err, "start_failed")
		}
	}
	p2 := m.ops.Probe(&eff, true)
	if !m.aligned(p2, &eff) {
		return orErr("post_install_version_mismatch", "installed %q, expected %q", p2.Version, want.Version)
	}
	return nil
}

// download fetches /api/agent/download/<file> from the enrolled server into
// dest (created exclusively). expectedSHA "" = manual install without
// manifest: the server's X-Content-SHA256 header is then mandatory.
func (m *obliReachManager) download(srv obliReachServer, file, dest string, size int64, expectedSHA string) (string, *orError) {
	url := strings.TrimRight(srv.URL, "/") + "/api/agent/download/" + file
	ctx, cancel := context.WithTimeout(context.Background(), orDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", orErr("download_failed", "%v", err)
	}
	if srv.APIKey != "" {
		req.Header.Set("X-Api-Key", srv.APIKey)
	}
	client := m.env.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", orErr("download_failed", "%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &orError{Code: "http_" + strconv.Itoa(resp.StatusCode)}
	}
	if expectedSHA == "" {
		expectedSHA = strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Content-SHA256")))
		if !orSHA256Re.MatchString(expectedSHA) {
			return "", orErr("no_hash", "the server sent no SHA-256 for %s", file)
		}
	}
	limit := size
	if limit <= 0 {
		limit = orMaxArtifactSize
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", orErr("download_failed", "create %s: %v", filepath.Base(dest), err)
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit+1))
	closeErr := f.Close()
	if copyErr != nil {
		return "", orErr("download_failed", "%v", copyErr)
	}
	if closeErr != nil {
		return "", orErr("download_failed", "%v", closeErr)
	}
	if (size > 0 && n != size) || n > orMaxArtifactSize || (resp.ContentLength >= 0 && n != resp.ContentLength) {
		return "", orErr("size_mismatch", "got %d bytes, expected %d", n, size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedSHA {
		return "", orErr("sha256_mismatch", "got %s…, expected %s…", shortHash(got), shortHash(expectedSHA))
	}
	return expectedSHA, nil
}

// verifyObliReachArtifact re-checks the staged file ON DISK (size + SHA-256
// are mandatory) and then runs the platform signature check (Authenticode
// on Windows, nothing elsewhere: the hash came over the authenticated push).
func verifyObliReachArtifact(path string, size int64, expectedSHA string, verifySig func(string) error) *orError {
	expectedSHA = strings.ToLower(strings.TrimSpace(expectedSHA))
	if !orSHA256Re.MatchString(expectedSHA) {
		return orErr("no_hash", "no valid SHA-256 to verify against")
	}
	f, err := os.Open(path)
	if err != nil {
		return orErr("download_failed", "open staged file: %v", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	f.Close()
	if err != nil {
		return orErr("download_failed", "read staged file: %v", err)
	}
	if (size > 0 && n != size) || n == 0 {
		return orErr("size_mismatch", "staged file has %d bytes, expected %d", n, size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedSHA {
		return orErr("sha256_mismatch", "staged file hash %s…, expected %s…", shortHash(got), shortHash(expectedSHA))
	}
	if verifySig != nil {
		if err := verifySig(path); err != nil {
			return asOrError(err, "signature_invalid")
		}
	}
	return nil
}

// InstallNow is the manual `install_oblireach` command: same verified
// pipeline, but no grace and no backoff (attempts reset). Refused while
// privacy mode is on.
//   - upgrade=false (the "(install)" action): a full reinstall when ObliReach
//     is already there (repairs a broken service or a stale server URL / API
//     key);
//   - upgrade=true (payload {mode:"upgrade"}, the "Update Reach" button):
//     nothing when the server's build is already installed; otherwise an
//     UPDATE (upgradeNeedsUninstall: plain `msiexec /i`, rolled back to the
//     installed build by Windows Installer when it fails) — never the
//     uninstall-then-install of a repair, which leaves no ObliReach at all
//     when the new build fails to install. An install already running
//     answers {status:"in_progress"} instead of an error.
//
// Whatever the mode, an install that did not complete restarts the
// installed build if it no longer runs (remote access is kept).
func (m *obliReachManager) InstallNow(srv obliReachServer, upgrade bool) (interface{}, error) {
	if m.env.privacy() {
		return nil, fmt.Errorf("privacy mode is enabled — ObliReach installation refused")
	}
	if !m.opMu.TryLock() {
		if upgrade {
			log.Printf("oblireach: manual update — an ObliReach installation is already in progress")
			return map[string]interface{}{"status": "in_progress"}, nil
		}
		return nil, fmt.Errorf("an ObliReach installation is already in progress")
	}
	defer m.opMu.Unlock()
	m.ensureLoaded()

	art := m.ops.ArtifactName()
	if art == "" {
		return nil, fmt.Errorf("ObliReach is not available for this OS/architecture")
	}
	if msg := m.ops.Precondition(false); msg != "" {
		return nil, fmt.Errorf("ObliReach cannot run on this machine: %s", msg)
	}
	if srv.URL == "" {
		srv = m.env.server()
	}

	want := m.getDesired()
	if want == nil || want.File == "" {
		// No manifest (older server or none received yet): fall back to the
		// download's X-Content-SHA256 header (mandatory) + signature check.
		want = &ObliReachDesired{Enabled: true, File: art}
	} else if state, msg := m.validateManifest(want); state != "" {
		return nil, fmt.Errorf("%s", msg)
	} else {
		m.syncTarget(want)
	}

	m.resetFailures()
	p := m.ops.Probe(want, true)
	if upgrade && want.Version != "" && m.aligned(p, want) && !m.st.Repair {
		// Already the server's build: nothing to install (a round makes sure
		// it runs).
		log.Printf("oblireach: manual update — ObliReach %s is already the server's build", p.Version)
		m.Kick()
		return map[string]interface{}{"status": "up_to_date", "version": p.Version}, nil
	}
	if b := m.busy(p); b != "" {
		log.Printf("oblireach: manual install refused — installer busy (%s)", b)
		m.setState(orStatePending, b, "", &p, want, m.env.now())
		return nil, fmt.Errorf("busy (%s) — retry in a few minutes", b)
	}
	uninstallFirst := p.Installed || m.st.ForceUninstall
	if upgrade {
		uninstallFirst = m.upgradeNeedsUninstall(p, want)
	}
	if oe := m.attemptInstall(want, p, uninstallFirst, srv); oe != nil {
		if !oe.Privacy {
			m.restartAfterFailedInstall(srv, want, oe)
		}
		switch {
		case oe.Privacy:
			return nil, fmt.Errorf("privacy mode was enabled during the installation — ObliReach left stopped")
		case oe.Busy != "":
			return nil, fmt.Errorf("busy (%s) — retry in a few minutes", oe.Busy)
		}
		return nil, oe
	}
	p2 := m.ops.Probe(want, true)
	method := "binary"
	if !m.ops.Traits().alignByHash {
		method = "msi"
	}
	return map[string]interface{}{"status": "installed", "method": method, "version": p2.Version}, nil
}

// restartAfterFailedInstall: a manual install / update did not complete — if
// an ObliReach build is still installed but no longer runs (stopped by the
// installer, or an uninstall step that failed half-way), start it so remote
// access is kept. Nothing under privacy mode, when none is installed, or when
// it runs / is starting.
func (m *obliReachManager) restartAfterFailedInstall(srv obliReachServer, want *ObliReachDesired, oe *orError) {
	if m.env.privacy() {
		return
	}
	p := m.ops.Probe(want, true)
	if (!p.Installed && !p.ServiceExists) || p.Running || p.Pending {
		return
	}
	why := oe.Error()
	if oe.Busy != "" {
		why = "installer busy (" + oe.Busy + ")"
	}
	log.Printf("oblireach: the manual install did not complete (%s) — starting the installed ObliReach %s so remote access is kept",
		why, p.Version)
	if err := m.ops.Start(srv); err != nil {
		log.Printf("oblireach: could not start ObliReach %s after the failed install: %v", p.Version, err)
	}
}

// PrivacyReleased runs when privacy mode goes from on to off (tray or
// remote), in place of the old "restart ObliReach". ObliReach was stopped
// (and disabled) the whole time, so it could not update itself:
//   - right build installed → started now;
//   - older build, stopped → the verified install runs right away (the MSI
//     re-creates the service in automatic start and starts it) — no grace,
//     and the backoff / busy retries booked before privacy mode are dropped
//     (stale context); the old build is NOT started first, which would race
//     its own self-update against this install;
//   - installer busy, remote session held, install failed, no usable target,
//     automatic install off → the installed build is started, so remote
//     access is never lost; the regular rounds take over.
//
// Serialised with the rounds and manual installs (opMu); a newer release
// supersedes one still waiting for the lock.
func (m *obliReachManager) PrivacyReleased() {
	gen := m.releaseGen.Add(1)
	m.opMu.Lock()
	defer m.opMu.Unlock()
	// Whatever happens, a round follows at once to publish the fresh state.
	defer m.Kick()
	if m.releaseGen.Load() != gen {
		return // a newer privacy release does the work
	}
	if m.env.privacy() {
		return // privacy mode already back on
	}
	srv := m.env.server()
	want := m.getDesired()
	if want == nil || m.ops.ArtifactName() == "" {
		m.startInstalled(srv, "no ObliReach target from the server")
		return
	}
	m.ensureLoaded()
	m.syncTarget(want)
	if !want.Enabled {
		m.startInstalled(srv, "automatic install is off")
		return
	}
	if state, msg := m.validateManifest(want); state != "" {
		m.startInstalled(srv, msg)
		return
	}
	if msg := m.ops.Precondition(true); msg != "" {
		m.startInstalled(srv, msg)
		return
	}

	now := m.env.now()
	p := m.ops.Probe(want, true)
	if !p.Installed && !p.ServiceExists {
		log.Printf("oblireach: privacy mode off — ObliReach is not installed (the regular round installs it)")
		return
	}
	if m.aligned(p, want) && !m.st.Repair {
		m.startAligned(srv, p, want, now)
		return
	}
	if p.Running {
		// Not stopped by privacy mode (or restarted by someone meanwhile):
		// its own update may be under way — the regular rounds decide.
		log.Printf("oblireach: privacy mode off — ObliReach %s already running, the regular round handles the update to %s", p.Version, want.Version)
		return
	}
	// Stopped the whole time: failures and busy retries booked before are
	// stale, and no self-update could run.
	m.resetFailures()
	m.st.SelfUpdateSince = time.Time{}
	if b := m.busy(p); b != "" {
		log.Printf("oblireach: privacy mode off — installer busy (%s): starting ObliReach %s for now, the update to %s follows", b, p.Version, want.Version)
		m.startInstalled(srv, "")
		return
	}
	if want.Hold {
		log.Printf("oblireach: privacy mode off — remote session held: starting ObliReach %s, the update to %s follows", p.Version, want.Version)
		m.startInstalled(srv, "")
		return
	}
	// Same rule as reconcileLocked: a plain `msiexec /i` (MajorUpgrade) for
	// an older build, uninstall first for a downgrade / repair.
	uninstallFirst := m.upgradeNeedsUninstall(p, want)
	log.Printf("oblireach: privacy mode off — installing ObliReach %s directly (installed=%q) instead of restarting the old build",
		want.Version, p.Version)
	oe := m.attemptInstall(want, p, uninstallFirst, srv)
	switch {
	case oe == nil:
		m.ensureRunning(srv, want)
	case oe.Privacy:
		// Privacy mode back on during the install: ObliReach stays stopped.
	default:
		why := oe.Error()
		if oe.Busy != "" {
			why = "installer busy (" + oe.Busy + ")"
		}
		log.Printf("oblireach: privacy mode off — the install did not complete (%s): starting the installed ObliReach %s so remote access is kept",
			why, p.Version)
		m.startInstalled(srv, "")
	}
}

// startInstalled starts whatever ObliReach is installed (privacy-release
// fallback, the former behaviour). Nothing when none is installed or privacy
// mode is on. `why` is logged when set.
func (m *obliReachManager) startInstalled(srv obliReachServer, why string) {
	if m.env.privacy() {
		return
	}
	p := m.ops.Probe(m.getDesired(), false)
	if !p.Installed && !p.ServiceExists {
		return
	}
	if why != "" {
		log.Printf("oblireach: privacy mode off — starting the installed ObliReach %s (%s)", p.Version, why)
	}
	if err := m.ops.Start(srv); err != nil {
		log.Printf("oblireach: could not start ObliReach after privacy mode: %v", err)
	}
}

// startAligned: the right build is installed — start it now (privacy
// release), booked like a start of handleAligned.
func (m *obliReachManager) startAligned(srv obliReachServer, p obliReachProbe, want *ObliReachDesired, now time.Time) {
	m.st.MismatchSince = time.Time{}
	m.st.SelfUpdateSince = time.Time{}
	m.clearBusyRetry()
	if p.Running {
		m.setState(orStateUpToDate, "", "", &p, want, now)
		return
	}
	log.Printf("oblireach: privacy mode off — ObliReach %s is up to date, starting it", p.Version)
	m.st.LastAttemptAt = now
	if err := m.ops.Start(srv); err != nil {
		m.recordStartFailure(asOrError(err, "start_failed"), now)
		m.setState(orStateFailed, "", m.st.LastError, &p, want, now)
		return
	}
	m.notRunningSince = time.Time{}
	m.awaitConfirmation(now)
	p2 := m.ops.Probe(want, true)
	m.setState(orStateUpToDate, "", "", &p2, want, m.env.now())
}

// ensureRunning: after a privacy-release install, make sure ObliReach runs
// (the MSI starts its service itself; this covers a service left disabled or
// stopped). A failure here is left to handleAligned's next rounds.
func (m *obliReachManager) ensureRunning(srv obliReachServer, want *ObliReachDesired) {
	if m.env.privacy() {
		return
	}
	p := m.ops.Probe(want, true)
	if p.Running || p.Pending {
		return
	}
	log.Printf("oblireach: ObliReach %s installed but not running — starting it", p.Version)
	if err := m.ops.Start(srv); err != nil {
		log.Printf("oblireach: could not start ObliReach %s after the install: %v", p.Version, err)
		return
	}
	p2 := m.ops.Probe(want, true)
	m.setState(orStateUpToDate, "", "", &p2, want, m.env.now())
}

// randomHex returns n random bytes hex-encoded (staging names).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}
