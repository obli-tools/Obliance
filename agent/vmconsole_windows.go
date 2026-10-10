//go:build windows

package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// ── VM interactive console (Hyper-V, "Layer B") ──────────────────────────────
//
// The agent spawns the bundled FreeRDP helper (vmconsole.exe), which connects
// to the VM's basic console (host 2179 + VM GUID pre-connection blob, SSO as
// the agent's SYSTEM identity — no stored credentials), captures the
// framebuffer and encodes H.264. This file bridges the helper to the SAME
// remote-tunnel relay as tunnel.go:
//
//   viewer <-> /api/remote/tunnel/{token} <-> server relay <->
//   /api/remote/agent-tunnel/{token} <-> THIS agent <-> helper stdin/stdout <-> VM
//
// Helper stdout: [1 byte type][uint32 LE len][payload]
//   'I' init  -> { u32 width, u32 height } -> JSON `init` (text frame)
//   'F' frame -> H.264 Annex-B             -> binary frame [0x02][annexb]
//   'S' status (protocol 2) -> JSON        -> `vm_state` / `error` (text)
// Viewer input (JSON text frames) is filtered (vmconsole_common.go) and
// written to the helper's stdin, one JSON line per message.
//
// The helper bundle (~130 MB unpacked: FreeRDP + x264 DLLs) is installed on
// demand into ProgramData\OblianceAgent\vmconsole\b-<sha12>\ (current.json
// points at the live one), verified against the SHA-256 the server sends.

func vmConsoleDir() string { return filepath.Join(configDir, "vmconsole") }

// vmcIsHyperVHost: the helper is only ever installed on a Hyper-V host
// (a variable for the tests, which run on machines without the role).
var vmcIsHyperVHost = func() bool { return detectVirtualizationHost() == "hyperv" }

// vmcCurrent is current.json: the installed bundle.
type vmcCurrent struct {
	SHA256      string `json:"sha256"`
	Dir         string `json:"dir"`
	InstalledAt string `json:"installedAt"`
	Protocol    int    `json:"protocol"`
	Built       string `json:"built,omitempty"`
	Signed      *bool  `json:"signed,omitempty"`
}

var vmcDirNameRe = regexp.MustCompile(`^b-[0-9a-f]{12}(-[0-9]+)?$`)

func vmcFileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func vmcReadProtocol(dir string) (int, string) {
	b, err := os.ReadFile(filepath.Join(dir, "vmconsole-version.txt"))
	if err != nil {
		return 1, ""
	}
	return parseHelperVersion(string(b))
}

// vmcInstalled returns the installed helper directory, or ok=false.
func vmcInstalled() (dir string, cur vmcCurrent, ok bool) {
	base := vmConsoleDir()
	if b, err := os.ReadFile(filepath.Join(base, "current.json")); err == nil {
		if json.Unmarshal(b, &cur) == nil && vmcDirNameRe.MatchString(cur.Dir) {
			d := filepath.Join(base, cur.Dir)
			if vmcFileExists(filepath.Join(d, "vmconsole.exe")) {
				return d, cur, true
			}
		}
	}
	// Flat layout of agents up to 4.5.84 (no hash recorded).
	if vmcFileExists(filepath.Join(base, "vmconsole.exe")) {
		p, built := vmcReadProtocol(base)
		return base, vmcCurrent{Dir: ".", Protocol: p, Built: built}, true
	}
	return "", vmcCurrent{}, false
}

// vmConsoleReportForPush is the push body's `vmConsole` (Hyper-V hosts only).
func vmConsoleReportForPush() *VmConsoleReport {
	if !vmcIsHyperVHost() {
		return nil
	}
	vmcStateMu.Lock()
	st := vmcState
	vmcStateMu.Unlock()
	if st == nil {
		vmcRefreshState("")
		vmcStateMu.Lock()
		st = vmcState
		vmcStateMu.Unlock()
	}
	if st == nil {
		return nil
	}
	cp := *st
	return &cp
}

// vmcRefreshState recomputes the reported state from disk (errText: the
// last install error, kept next to an older install still in place).
func vmcRefreshState(errText string) {
	if _, cur, ok := vmcInstalled(); ok {
		setVMConsoleState(VmConsoleReport{State: "installed", SHA256: cur.SHA256, InstalledAt: cur.InstalledAt,
			Protocol: cur.Protocol, Built: cur.Built, Signed: cur.Signed, Error: errText})
		return
	}
	if errText != "" {
		setVMConsoleState(VmConsoleReport{State: "error", Error: errText})
		return
	}
	setVMConsoleState(VmConsoleReport{State: "not_installed"})
}

// ── Install (single flight) ──────────────────────────────────────────────────

type vmcJob struct {
	done      chan struct{}
	dir       string
	cur       vmcCurrent
	err       error
	mu        sync.Mutex
	listeners []func(phase string, pct int)
}

func (j *vmcJob) addListener(f func(phase string, pct int)) {
	j.mu.Lock()
	j.listeners = append(j.listeners, f)
	j.mu.Unlock()
}

func (j *vmcJob) emit(phase string, pct int) {
	j.mu.Lock()
	ls := append([]func(string, int){}, j.listeners...)
	j.mu.Unlock()
	for _, f := range ls {
		f(phase, pct)
	}
}

var (
	vmcJobMu  sync.Mutex
	vmcJobCur *vmcJob
)

// vmcEnsure returns an installed helper, installing it (force: reinstalling
// it) when needed. Concurrent callers share ONE download (a second click,
// an automatic install and a console opening at the same time).
func (d *CommandDispatcher) vmcEnsure(force bool, progress func(phase string, pct int)) (dir string, cur vmcCurrent, already bool, err error) {
	if !force {
		if dir, cur, ok := vmcInstalled(); ok {
			return dir, cur, true, nil
		}
	}
	vmcJobMu.Lock()
	job := vmcJobCur
	if job == nil {
		job = &vmcJob{done: make(chan struct{})}
		vmcJobCur = job
		go func() {
			defer func() {
				if r := recover(); r != nil {
					job.err = fmt.Errorf("internal error during install: %v", r)
				}
				vmcJobMu.Lock()
				vmcJobCur = nil
				vmcJobMu.Unlock()
				close(job.done)
			}()
			job.dir, job.cur, job.err = d.vmcInstall(force, job.emit)
		}()
	} else {
		log.Printf("vm console: install already in progress — joining it")
	}
	vmcJobMu.Unlock()
	if progress != nil {
		job.addListener(progress)
	}
	<-job.done
	return job.dir, job.cur, false, job.err
}

func (d *CommandDispatcher) vmcHTTPClient() *http.Client {
	cfg := serverTLSConfig()
	if d.tlsInsecureSkipVerify {
		cfg = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   45 * time.Minute,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: cfg, ResponseHeaderTimeout: 60 * time.Second},
	}
}

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// vmcFreeBytes: free space available to the agent on dir's volume.
func vmcFreeBytes(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, err
	}
	return avail, nil
}

// vmcFileError explains a file system failure (antivirus quarantine, file
// in use, access denied) instead of a bare Win32 text.
func vmcFileError(what string, err error) error {
	var en syscall.Errno
	if errors.As(err, &en) {
		switch en {
		case windows.ERROR_ACCESS_DENIED:
			return fmt.Errorf("%s: access denied (an antivirus may have blocked or quarantined the console files): %v", what, err)
		case windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION:
			return fmt.Errorf("%s: file in use by another process (antivirus scan or a console still open): %v", what, err)
		case windows.ERROR_DISK_FULL, windows.ERROR_HANDLE_DISK_FULL:
			return fmt.Errorf("%s: disk full: %v", what, err)
		case windows.ERROR_VIRUS_INFECTED, windows.ERROR_VIRUS_DELETED:
			return fmt.Errorf("%s: blocked by the antivirus (file reported as a threat): %v", what, err)
		}
	}
	return fmt.Errorf("%s: %v", what, err)
}

type vmcCountingWriter struct {
	n      int64
	total  int64
	onTick func(written, total int64)
}

func (c *vmcCountingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	if c.onTick != nil {
		c.onTick(c.n, c.total)
	}
	return len(p), nil
}

const (
	vmcMaxUnpacked = 2 << 30 // 2 GiB: a zip bomb never fills the disk
	vmcMaxFiles    = 4000
)

// vmcInstall downloads, verifies and unpacks the helper bundle.
func (d *CommandDispatcher) vmcInstall(force bool, emit func(phase string, pct int)) (string, vmcCurrent, error) {
	start := time.Now()
	_, prev, hadPrev := vmcInstalled()
	report := func(phase string, pct int) {
		setVMConsoleState(VmConsoleReport{State: "installing", Phase: phase, Percent: pct, SHA256: prev.SHA256})
		emit(phase, pct)
	}
	fail := func(err error) (string, vmcCurrent, error) {
		log.Printf("vm console: install FAILED after %s: %v", time.Since(start).Round(time.Second), err)
		if hadPrev {
			vmcRefreshState(err.Error())
		} else {
			setVMConsoleState(VmConsoleReport{State: "error", Error: truncateStr(err.Error(), 500)})
		}
		return "", vmcCurrent{}, err
	}
	if !vmcIsHyperVHost() {
		return fail(fmt.Errorf("this host is not a Hyper-V host: the VM console is not installed"))
	}
	base := vmConsoleDir()
	if err := os.MkdirAll(base, 0o755); err != nil {
		return fail(vmcFileError("cannot create "+base, err))
	}
	log.Printf("vm console: installing the helper bundle (force=%v)…", force)
	report("download", 0)

	url := strings.TrimRight(d.serverURL, "/") + "/api/agent/download/vmconsole.zip"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("X-Api-Key", d.apiKey)
	resp, err := d.vmcHTTPClient().Do(req)
	if err != nil {
		return fail(fmt.Errorf("download failed: %v", err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fail(fmt.Errorf("download failed: the server has no console bundle (vmconsole.zip missing from this release)"))
	case resp.StatusCode != http.StatusOK:
		return fail(fmt.Errorf("download failed: the server answered HTTP %d", resp.StatusCode))
	}
	expected := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Content-SHA256")))
	if !sha256HexRe.MatchString(expected) {
		return fail(fmt.Errorf("download refused: the server sent no integrity hash (X-Content-SHA256)"))
	}
	total := resp.ContentLength
	need := uint64(400 << 20)
	if total > 0 {
		need = uint64(total)*4 + 64<<20 // zip + unpacked (~2.6x) + margin
	}
	if free, ferr := vmcFreeBytes(base); ferr == nil && free < need {
		return fail(fmt.Errorf("not enough disk space on %s: %d MB free, %d MB needed",
			filepath.VolumeName(base), free>>20, need>>20))
	}

	tmp := filepath.Join(base, fmt.Sprintf("download-%d.zip.part", os.Getpid()))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fail(vmcFileError("cannot write the download", err))
	}
	defer os.Remove(tmp)
	h := sha256.New()
	thr := &progressThrottle{step: 2, every: 2 * time.Second}
	cw := &vmcCountingWriter{total: total, onTick: func(n, t int64) {
		if t <= 0 {
			return
		}
		pct := int(n * 100 / t)
		if pct > 100 {
			pct = 100
		}
		if thr.allow("download", pct, time.Now()) {
			report("download", pct)
		}
	}}
	written, err := io.Copy(io.MultiWriter(f, h, cw), resp.Body)
	cerr := f.Close()
	if err != nil {
		return fail(fmt.Errorf("download interrupted after %d MB: %v", written>>20, err))
	}
	if cerr != nil {
		return fail(vmcFileError("cannot write the download", cerr))
	}
	if total > 0 && written != total {
		return fail(fmt.Errorf("download truncated (%d of %d bytes)", written, total))
	}

	report("verify", 100)
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fail(fmt.Errorf("integrity check failed: SHA-256 %s instead of %s (download corrupted or altered) — nothing installed", got[:16], expected[:16]))
	}

	dirName := "b-" + expected[:12]
	final := filepath.Join(base, dirName)
	if vmcFileExists(filepath.Join(final, "vmconsole.exe")) && !force {
		// Same build already unpacked (current.json lost): reuse it.
		log.Printf("vm console: bundle %s already unpacked", dirName)
	} else {
		if _, err := os.Stat(final); err == nil {
			// Repair, or a damaged folder that may be in use: a new name.
			dirName = fmt.Sprintf("%s-%d", dirName, time.Now().Unix())
			final = filepath.Join(base, dirName)
		}
		stage := final + ".staging"
		_ = os.RemoveAll(stage)
		report("extract", 0)
		thrX := &progressThrottle{step: 10, every: 2 * time.Second}
		if err := vmcUnzip(tmp, stage, func(pct int) {
			if thrX.allow("extract", pct, time.Now()) {
				report("extract", pct)
			}
		}); err != nil {
			_ = os.RemoveAll(stage)
			return fail(err)
		}
		if !vmcFileExists(filepath.Join(stage, "vmconsole.exe")) {
			_ = os.RemoveAll(stage)
			return fail(fmt.Errorf("invalid bundle: vmconsole.exe missing from the archive"))
		}
		if err := os.Rename(stage, final); err != nil {
			_ = os.RemoveAll(stage)
			return fail(vmcFileError("cannot activate the new console files", err))
		}
	}

	// Authenticode: a SIGNED helper must be signed by this agent's publisher
	// (a foreign signature is refused); an unsigned one is accepted on the
	// strength of the SHA-256 above and reported as unsigned.
	exe := filepath.Join(final, "vmconsole.exe")
	signed := false
	if trustErr := winVerifyTrustFile(exe, IsAirgapMode()); trustErr == nil || isChainTrustError(trustErr) {
		if _, sErr := readAuthenticodeSigner(exe); sErr == nil {
			if vErr := verifyObliReachSigner(exe); vErr != nil {
				_ = os.RemoveAll(final)
				return fail(fmt.Errorf("signature check failed: vmconsole.exe %v", vErr))
			}
			signed = true
		}
	}

	protocol, built := vmcReadProtocol(final)
	cur := vmcCurrent{SHA256: expected, Dir: dirName, InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Protocol: protocol, Built: built, Signed: &signed}
	b, _ := json.MarshalIndent(cur, "", "  ")
	curTmp := filepath.Join(base, "current.json.tmp")
	if err := os.WriteFile(curTmp, b, 0o644); err != nil {
		return fail(vmcFileError("cannot record the installed version", err))
	}
	if err := os.Rename(curTmp, filepath.Join(base, "current.json")); err != nil {
		return fail(vmcFileError("cannot record the installed version", err))
	}
	vmcCleanup(base, dirName)
	setVMConsoleState(VmConsoleReport{State: "installed", SHA256: cur.SHA256, InstalledAt: cur.InstalledAt,
		Protocol: cur.Protocol, Built: cur.Built, Signed: cur.Signed})
	emit("done", 100)
	log.Printf("vm console: helper %s installed in %s (%d MB, protocol %d, signed=%v)",
		dirName, time.Since(start).Round(time.Second), written>>20, protocol, signed)
	return final, cur, nil
}

// vmcUnzip extracts the (flat) bundle into dir, bounded in size and count.
func vmcUnzip(zipPath, dir string, progress func(pct int)) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("extraction failed: not a valid archive: %v", err)
	}
	defer r.Close()
	if len(r.File) > vmcMaxFiles {
		return fmt.Errorf("extraction refused: %d files in the archive", len(r.File))
	}
	var sum uint64
	for _, zf := range r.File {
		sum += zf.UncompressedSize64
	}
	if sum > vmcMaxUnpacked {
		return fmt.Errorf("extraction refused: archive unpacks to %d MB", sum>>20)
	}
	if free, ferr := vmcFreeBytes(filepath.Dir(dir)); ferr == nil && free < sum+32<<20 {
		return fmt.Errorf("not enough disk space to unpack: %d MB free, %d MB needed", free>>20, (sum+32<<20)>>20)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return vmcFileError("cannot create "+dir, err)
	}
	var done uint64
	for i, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(zf.Name) // flat: never a path outside dir
		if name == "." || name == ".." || name == "" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("extraction failed (%s): %v", name, err)
		}
		out, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return vmcFileError("extraction failed ("+name+")", err)
		}
		n, cerr := io.Copy(out, io.LimitReader(rc, int64(zf.UncompressedSize64)+1))
		oerr := out.Close()
		rc.Close()
		if cerr != nil {
			return vmcFileError("extraction failed ("+name+")", cerr)
		}
		if oerr != nil {
			return vmcFileError("extraction failed ("+name+")", oerr)
		}
		if uint64(n) != zf.UncompressedSize64 {
			return fmt.Errorf("extraction failed (%s): size mismatch", name)
		}
		done += zf.UncompressedSize64
		if progress != nil && sum > 0 {
			progress(int(done * 100 / sum))
		} else if progress != nil {
			progress((i + 1) * 100 / len(r.File))
		}
	}
	return nil
}

// vmcCleanup removes older bundles (best effort: one still used by an open
// console is locked and goes at a later install).
func vmcCleanup(base, keep string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir() && name != keep && (vmcDirNameRe.MatchString(name) || strings.HasSuffix(name, ".staging")):
			_ = os.RemoveAll(filepath.Join(base, name))
		case !e.IsDir() && (strings.HasSuffix(strings.ToLower(name), ".dll") || strings.EqualFold(name, "vmconsole.exe") || strings.EqualFold(name, "vmconsole-version.txt")):
			// Flat layout of agents up to 4.5.84.
			_ = os.Remove(filepath.Join(base, name))
		}
	}
}

// handleInstallVmConsole installs / repairs the helper (Tasks: "Install the
// VM console"). Payload: { force?: bool }.
func (d *CommandDispatcher) handleInstallVmConsole(cmd AgentCommand) (interface{}, error) {
	if !vmcIsHyperVHost() {
		return nil, fmt.Errorf("this host is not a Hyper-V host: the VM console is not installed")
	}
	force, _ := cmd.Payload["force"].(bool)
	// The server names the bundle it wants (sha256): an installed helper of
	// another build is NOT "already installed" — it is replaced. (Otherwise
	// "Update" on an outdated helper ends in 5 ms with nothing replaced.)
	if want, _ := cmd.Payload["sha256"].(string); !force && sha256HexRe.MatchString(strings.ToLower(want)) {
		if _, cur, ok := vmcInstalled(); ok && !strings.EqualFold(cur.SHA256, want) {
			log.Printf("vm console: installed helper %.12s is not the wanted build %.12s — replacing it", cur.SHA256, want)
			force = true
		}
	}
	start := time.Now()
	d.reportCommandProgress(cmd.ID, cmd.Type, map[string]interface{}{"phase": "start", "percent": 0})
	dir, cur, already, err := d.vmcEnsure(force, func(phase string, pct int) {
		d.reportCommandProgress(cmd.ID, cmd.Type, map[string]interface{}{"phase": phase, "percent": pct})
	})
	if err != nil {
		return nil, err
	}
	return vmcInstallResult(dir, cur, already, start), nil
}

func vmcInstallResult(dir string, cur vmcCurrent, already bool, start time.Time) map[string]interface{} {
	status := "installed"
	if already {
		status = "already_installed"
	}
	r := map[string]interface{}{
		"status": status, "path": dir, "sha256": cur.SHA256, "protocol": cur.Protocol,
		"installedAt": cur.InstalledAt, "durationMs": time.Since(start).Milliseconds(),
	}
	if cur.Signed != nil {
		r["signed"] = *cur.Signed
	}
	return r
}

// ── Sessions ─────────────────────────────────────────────────────────────────

type vmConsoleSession struct {
	token     string
	vmID      string
	closeOnce sync.Once
	closeFn   func()
}

func (s *vmConsoleSession) close() { s.closeOnce.Do(func() { s.closeFn() }) }

var (
	vmConsolesMu sync.Mutex
	vmConsoles   = map[string]*vmConsoleSession{}
)

// closeVmConsoleByToken ends a console session (close_vm_console, or the
// close_remote_tunnel the server sends when a session ends).
func closeVmConsoleByToken(token string) bool {
	vmConsolesMu.Lock()
	s := vmConsoles[token]
	vmConsolesMu.Unlock()
	if s == nil {
		return false
	}
	s.close()
	return true
}

// handleCloseVmConsole stops an active VM console session by token.
func (d *CommandDispatcher) handleCloseVmConsole(cmd AgentCommand) (interface{}, error) {
	token := payloadString(cmd.Payload, "sessionToken")
	if !closeVmConsoleByToken(token) {
		return map[string]string{"status": "not_found"}, nil
	}
	return map[string]string{"status": "vm_console_closed"}, nil
}

// vmcHostIsNT6: Windows NT 6.x (7 / 8 / 8.1, Server 2008 R2 / 2012 / 2012 R2),
// where the helper bundle cannot be loaded. A variable for the tests.
var vmcHostIsNT6 = func() bool {
	v := windows.RtlGetVersion()
	return v != nil && v.MajorVersion < 10
}

// vmcStateOf: vmStateOf, a variable for the bridge tests.
var vmcStateOf = vmStateOf

// vmStateOf returns the Hyper-V state of a VM ("Running", "Off", ...), or ""
// when it cannot be told (old host, slow WMI: the console then just tries).
func vmStateOf(vmID string) (string, error) {
	if hyperVUsesWMIv1() {
		return "", nil
	}
	out, err := psOutputTimeout(hyperVStateTimeout, false,
		fmt.Sprintf("$ErrorActionPreference='Stop'; (Get-VM -Id '%s').State.ToString()", psEscape(vmID)))
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "unable to find a virtual machine") || strings.Contains(low, "impossible de trouver") ||
			strings.Contains(low, "objectnotfound") {
			return "", vmErr(vmErrNotFound, "This virtual machine no longer exists on this host.")
		}
		return "", nil
	}
	return strings.TrimSpace(string(out)), nil
}

// stderrTail keeps the last bytes the helper wrote on stderr (diagnostics).
type stderrTail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *stderrTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > 4096 {
		t.buf = t.buf[len(t.buf)-4096:]
	}
	t.mu.Unlock()
	return len(p), nil
}

// lastLines returns the last n non-empty lines (the whole FreeRDP diagnostic
// around a failure, not only its last line, which is often truncated).
func (t *stderrTail) lastLines(n int) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for _, l := range strings.Split(string(t.buf), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

func (t *stderrTail) lastLine() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(t.buf)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (d *CommandDispatcher) handleOpenVmConsole(cmd AgentCommand) (interface{}, error) {
	sessionToken := payloadString(cmd.Payload, "sessionToken")
	if sessionToken == "" {
		return nil, fmt.Errorf("open_vm_console: missing sessionToken")
	}
	vmID := payloadString(cmd.Payload, "vmId")
	if !validVMGUID(vmID) {
		return nil, fmt.Errorf("open_vm_console: invalid vmId")
	}
	installCmdID := payloadString(cmd.Payload, "installCommandId")
	installPolicy := payloadString(cmd.Payload, "installPolicy") // auto | manual | frozen ("" = older server)

	// Relay first: the viewer then sees every step (install progress, VM
	// off, helper failure) instead of a silent wait.
	base := strings.TrimRight(d.serverURL, "/")
	var wsBase string
	switch {
	case strings.HasPrefix(base, "https://"):
		wsBase = "wss://" + base[8:]
	case strings.HasPrefix(base, "http://"):
		wsBase = "ws://" + base[7:]
	default:
		wsBase = base
	}
	var tlsCfg *tls.Config
	if d.tlsInsecureSkipVerify {
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	}
	ws, err := wsConnect(wsBase+"/api/remote/agent-tunnel/"+sessionToken, http.Header{"X-Api-Key": []string{d.apiKey}}, tlsCfg)
	if err != nil {
		if installCmdID != "" {
			d.finishCommand(installCmdID, "install_vm_console", nil, fmt.Errorf("not started: the console relay could not be reached (%v)", err))
		}
		return nil, vmErr(vmErrRelay, "relay WebSocket connect failed: %v", err)
	}

	var wsMu sync.Mutex
	send := func(op byte, b []byte) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return ws.WriteFrame(op, b)
	}

	closeCh := make(chan struct{})
	var (
		helperMu  sync.Mutex
		helperCmd *os.Process
		jobHandle syscall.Handle = syscall.InvalidHandle
		stdinW    io.WriteCloser
		closing   bool
	)
	inputCh := make(chan []byte, 512)
	var protocol = 1

	sess := &vmConsoleSession{token: sessionToken, vmID: vmID}
	sess.closeFn = func() {
		helperMu.Lock()
		closing = true
		p, job, in := helperCmd, jobHandle, stdinW
		jobHandle = syscall.InvalidHandle
		helperMu.Unlock()
		close(closeCh)
		ws.Close()
		if in != nil {
			_ = in.Close()
		}
		if p != nil {
			_ = p.Kill()
		}
		if job != syscall.InvalidHandle {
			syscall.CloseHandle(job) // kills anything left in the job
		}
		vmConsolesMu.Lock()
		if vmConsoles[sessionToken] == sess {
			delete(vmConsoles, sessionToken)
		}
		vmConsolesMu.Unlock()
		log.Printf("vm console: session closed (vm=%s)", vmID)
	}
	// One console per VM on this host: an older session on the same VM is
	// closed (Hyper-V would disconnect it anyway when this one connects).
	vmConsolesMu.Lock()
	var olds []*vmConsoleSession
	for t, s := range vmConsoles {
		if s.vmID == vmID && t != sessionToken {
			olds = append(olds, s)
		}
	}
	vmConsoles[sessionToken] = sess
	vmConsolesMu.Unlock()
	for _, s := range olds {
		s.close()
	}

	// fail: tell the viewer (coded error), then end the session.
	fail := func(e *vmCodedError) (interface{}, error) {
		_ = send(0x1, vmRelayError(e))
		time.Sleep(300 * time.Millisecond)
		sess.close()
		return nil, e
	}

	// Keepalive so proxies don't drop the relay.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-closeCh:
				return
			case <-t.C:
				if send(0x9, nil) != nil {
					sess.close()
					return
				}
			}
		}
	}()

	// Viewer -> helper input (dropped until the helper runs).
	go func() {
		defer sess.close()
		for {
			opcode, payload, err := ws.ReadFrame()
			if err != nil {
				return
			}
			switch opcode {
			case 0x8:
				return
			case 0x9:
				_ = send(0xA, payload)
			case 0x1:
				helperMu.Lock()
				running, proto := stdinW != nil, protocol
				helperMu.Unlock()
				if !running {
					continue
				}
				line, ok := filterVMConsoleInput(payload, proto)
				if !ok {
					continue
				}
				select {
				case inputCh <- line:
				default:
					if isDroppableInput(line) {
						continue // the helper lags: a later move supersedes this one
					}
					select {
					case inputCh <- line:
					case <-closeCh:
						return
					}
				}
			}
		}
	}()

	_ = send(0x1, vmStateMessage("preparing", nil))

	// The VM must be running (paused: the console shows its frozen screen).
	if st, serr := vmcStateOf(vmID); serr != nil {
		var ce *vmCodedError
		if errors.As(serr, &ce) {
			if installCmdID != "" {
				d.finishCommand(installCmdID, "install_vm_console", nil, fmt.Errorf("not started: %s", ce.Message))
			}
			return fail(ce)
		}
	} else if st != "" {
		switch strings.ToLower(st) {
		case "off", "offcritical", "stopping":
			if installCmdID != "" {
				d.finishCommand(installCmdID, "install_vm_console", nil, fmt.Errorf("not started: the VM is turned off"))
			}
			return fail(vmErr(vmErrOff, "The virtual machine is turned off. Start it, then open the console again."))
		case "saved", "savedcritical", "saving":
			if installCmdID != "" {
				d.finishCommand(installCmdID, "install_vm_console", nil, fmt.Errorf("not started: the VM is in saved state"))
			}
			return fail(vmErr(vmErrOff, "The virtual machine is in saved state. Start it, then open the console again."))
		}
	}

	// Helper: installed, or installed now (on demand, unless the policy
	// forbids it) — a visible task when the server created one.
	start := time.Now()
	helperDir, cur, ok := vmcInstalled()
	if ok {
		if installCmdID != "" {
			d.finishCommand(installCmdID, "install_vm_console", vmcInstallResult(helperDir, cur, true, start), nil)
		}
	} else {
		if installPolicy == "frozen" {
			if installCmdID != "" {
				d.finishCommand(installCmdID, "install_vm_console", nil, fmt.Errorf("not installed: disabled by the VM console policy"))
			}
			return fail(vmErr(vmErrDisabled, "The VM console component is not installed on this host and its installation is disabled by policy."))
		}
		_ = send(0x1, vmStateMessage("installing", map[string]interface{}{"phase": "download", "percent": 0}))
		vthr := &progressThrottle{step: 2, every: time.Second}
		var derr error
		helperDir, cur, _, derr = d.vmcEnsure(false, func(phase string, pct int) {
			if vthr.allow(phase, pct, time.Now()) {
				_ = send(0x1, vmStateMessage("installing", map[string]interface{}{"phase": phase, "percent": pct}))
			}
			if installCmdID != "" {
				d.reportCommandProgress(installCmdID, "install_vm_console", map[string]interface{}{"phase": phase, "percent": pct})
			}
		})
		if installCmdID != "" {
			if derr != nil {
				d.finishCommand(installCmdID, "install_vm_console", nil, derr)
			} else {
				d.finishCommand(installCmdID, "install_vm_console", vmcInstallResult(helperDir, cur, false, start), nil)
			}
		}
		if derr != nil {
			return fail(vmErr(vmErrInstallFailed, "The VM console component could not be installed: %v", derr))
		}
	}
	select {
	case <-closeCh:
		return nil, fmt.Errorf("open_vm_console: the viewer left before the console started")
	default:
	}

	helper := filepath.Join(helperDir, "vmconsole.exe")
	proto, _ := vmcReadProtocol(helperDir)

	hc := hiddenCmd(helper, vmID, "-", "0")
	hc.Dir = helperDir
	hc.Env = append(os.Environ(), "OPENSSL_MODULES="+helperDir)
	stderr := &stderrTail{}
	hc.Stderr = stderr
	stdout, err := hc.StdoutPipe()
	if err != nil {
		return fail(vmErr(vmErrHelperStart, "%v", err))
	}
	stdin, err := hc.StdinPipe()
	if err != nil {
		return fail(vmErr(vmErrHelperStart, "%v", err))
	}
	_ = send(0x1, vmStateMessage("starting", nil))
	if err := hc.Start(); err != nil {
		return fail(vmErr(vmErrHelperStart, "%v", vmcFileError("the console helper could not be started", err)))
	}
	// Job object: the helper dies with this session — and with the agent.
	job, jerr := createJobObject()
	if jerr == nil {
		if h, _, _ := procOpenProcess.Call(_PROCESS_ALL_ACCESS, 0, uintptr(hc.Process.Pid)); h != 0 {
			procAssignProcess.Call(uintptr(job), h)
			syscall.CloseHandle(syscall.Handle(h))
		}
	}
	helperMu.Lock()
	if closing {
		helperMu.Unlock()
		_ = hc.Process.Kill()
		if jerr == nil {
			syscall.CloseHandle(job)
		}
		return nil, fmt.Errorf("open_vm_console: the viewer left before the console started")
	}
	helperCmd, stdinW, protocol = hc.Process, stdin, proto
	if jerr == nil {
		jobHandle = job
	}
	helperMu.Unlock()

	// Input writer: one JSON line per message.
	go func() {
		for {
			select {
			case <-closeCh:
				return
			case line := <-inputCh:
				if _, err := stdin.Write(append(line, '\n')); err != nil {
					return
				}
			}
		}
	}()

	// Helper framed stdout -> viewer. The reaper below waits for this reader
	// (exec: Wait must not run before the pipe is drained), so a last 'S'
	// "ended" status always reaches the viewer before the session closes.
	var endedRelayed atomic.Bool
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		r := bufio.NewReaderSize(stdout, 1<<20)
		hdr := make([]byte, 5)
		for {
			if _, err := io.ReadFull(r, hdr); err != nil {
				return
			}
			n := binary.LittleEndian.Uint32(hdr[1:5])
			if n > 64<<20 {
				log.Printf("vm console: helper frame too large (%d bytes) — closing", n)
				sess.close()
				return
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(r, payload); err != nil {
				return
			}
			var werr error
			switch hdr[0] {
			case 'I':
				if n >= 8 {
					w := binary.LittleEndian.Uint32(payload[0:4])
					h := binary.LittleEndian.Uint32(payload[4:8])
					werr = send(0x1, vmInitMessage(w, h, proto))
				}
			case 'F':
				frame := make([]byte, 0, n+1)
				frame = append(frame, 0x02) // viewer frame type: H.264
				frame = append(frame, payload...)
				werr = send(0x2, frame)
			case 'S':
				msg, terminal, ok := mapHelperStatus(payload)
				if terminal {
					endedRelayed.Store(true)
				}
				if ok {
					werr = send(0x1, msg)
				}
			}
			if werr != nil {
				sess.close() // viewer gone: stop the helper
				return
			}
		}
	}()

	// Reap the helper; an exit without a reason still tells the viewer why.
	go func() {
		<-readerDone
		werr := hc.Wait()
		code := 0
		if hc.ProcessState != nil {
			code = hc.ProcessState.ExitCode()
		}
		helperMu.Lock()
		byUs := closing
		helperMu.Unlock()
		tail := stderr.lastLine()
		log.Printf("vm console: helper exited (vm=%s code=%d err=%v) %s", vmID, code, werr, truncateStr(tail, 300))
		if code != 0 && !byUs {
			for _, l := range stderr.lastLines(20) {
				log.Printf("vm console: helper stderr: %s", truncateStr(l, 400))
			}
		}
		if !byUs && !endedRelayed.Load() && code != 0 {
			e := vmErr(vmErrEnded, "The console helper stopped (exit code %d). %s", code, truncateStr(tail, 200))
			switch uint32(code) {
			case 4:
				e = vmErr(vmErrConnectFailed, "The VM console could not be reached on this host. %s", truncateStr(tail, 200))
			case 0xC0000139, 0xC0000135, 0xC0000142, 0xC000007B:
				if vmcHostIsNT6() {
					// Windows 8 / 2012 / 2012 R2 / 7: the bundled FreeRDP 3 +
					// FFmpeg DLLs target Windows 10 (e.g. ProcessPrng): the
					// loader refuses them, a repair cannot help.
					e = vmErr(vmErrOSUnsupported, "The VM console component cannot run on this Windows version (needs Windows Server 2016 / Windows 10 or later; loader code 0x%08X).", uint32(code))
					break
				}
				if uint32(code) == 0xC0000139 {
					e = vmErr(vmErrHelperStart, "The console component does not match this Windows version (entry point not found, code 0xC0000139): use \"Repair\" on the device's Hyper-V tab.")
					break
				}
				// DLL not found / failed to initialise / bad image: a damaged
				// bundle (or files quarantined by an antivirus).
				e = vmErr(vmErrHelperStart, "The console component is damaged on this host (a DLL is missing or blocked, code 0x%08X): use \"Repair\" on the device's Hyper-V tab.", uint32(code))
			}
			_ = send(0x1, vmRelayError(e))
			time.Sleep(200 * time.Millisecond)
		}
		sess.close()
	}()

	log.Printf("Command %s: vm console open (vm=%s protocol=%d, helper %s)", cmd.ID, vmID, proto, filepath.Base(helperDir))
	return map[string]interface{}{"status": "vm_console_open", "sessionToken": sessionToken, "protocol": proto}, nil
}
