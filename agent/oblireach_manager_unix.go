//go:build !windows

package main

// Linux / macOS OS actions of the ObliReach manager (see oblireach_manager.go).
//
// ObliReach has no service unit on these platforms: this agent supervises it
// (pidfile + process scan), launches it detached (setsid) WITHOUT the API key
// on its command line (the key goes into /etc/oblireach-agent/config.json,
// mode 0600), replaces the binary atomically (rename) and stops it with
// SIGTERM then SIGKILL — including for privacy mode, which before this only
// acted on Windows.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

const (
	obliReachConfigDirUnix = "/etc/oblireach-agent" // ObliReach's own config dir (config.json, version.txt)
	obliReachPidFileName   = "oblireach.pid"        // in this agent's configDir
	obliReachConfirmDelay  = 10 * time.Second
	obliReachStopTimeout   = 5 * time.Second
)

type unixObliReachOps struct {
	mu sync.Mutex // serialises stop / launch / binary replacement

	hashMu    sync.Mutex
	hashSize  int64
	hashMtime time.Time
	hashSum   string
}

var obliReachPlatformOps obliReachOps = &unixObliReachOps{}

func obliReachUnixOps() *unixObliReachOps { return obliReachPlatformOps.(*unixObliReachOps) }

// obliReachUnixStop is the privacy-mode stop on Linux/macOS.
func obliReachUnixStop() {
	obliReachUnixOps().Stop()
}

// (Privacy mode lifted: the manager relaunches — or first updates — ObliReach,
// see obliReachManager.PrivacyReleased.)

func (u *unixObliReachOps) binaryPath() string {
	return filepath.Join(obliReachInstallDir(), obliReachBinaryFileName())
}

func (u *unixObliReachOps) pidFile() string {
	return filepath.Join(configDir, obliReachPidFileName)
}

func (u *unixObliReachOps) Traits() obliReachTraits {
	return obliReachTraits{
		alignByHash:       true,
		selfUpdates:       false, // ObliReach never updates itself outside Windows
		startAfterInstall: true,
		notRunningGrace:   45 * time.Second, // i.e. start at the next round
	}
}

func (u *unixObliReachOps) ArtifactName() string {
	return obliReachArtifactName(runtime.GOOS, runtime.GOARCH)
}

// ── Precondition (Linux: X11) ───────────────────────────────────────────────

var obliReachLibDirs = []string{
	"/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
	"/usr/lib64", "/lib64", "/usr/lib", "/lib", "/usr/local/lib",
}

func obliReachLibPresent(name string) bool {
	for _, d := range obliReachLibDirs {
		if _, err := os.Stat(filepath.Join(d, name)); err == nil {
			return true
		}
	}
	return false
}

// firstX11Display returns ":N" for the lowest /tmp/.X11-unix/XN socket, or "".
func firstX11Display() string {
	entries, err := os.ReadDir("/tmp/.X11-unix")
	if err != nil {
		return ""
	}
	best := -1
	for _, e := range entries {
		n := strings.TrimPrefix(e.Name(), "X")
		if n == e.Name() {
			continue
		}
		if v, err := strconv.Atoi(n); err == nil && (best < 0 || v < best) {
			best = v
		}
	}
	if best < 0 {
		return ""
	}
	return ":" + strconv.Itoa(best)
}

// Precondition: the Linux ObliReach build links libX11/libXrandr/libXtst and
// captures an X display; a headless server gets `unsupported: no_display`
// instead of a binary that cannot work. strict=false (manual install) only
// requires the libraries.
func (u *unixObliReachOps) Precondition(strict bool) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	for _, lib := range []string{"libX11.so.6", "libXrandr.so.2", "libXtst.so.6"} {
		if !obliReachLibPresent(lib) {
			return "no_display: X11 libraries missing (" + lib + ")"
		}
	}
	if strict && firstX11Display() == "" {
		return "no_display: no X11 display on this machine (/tmp/.X11-unix is empty)"
	}
	return ""
}

// ── Probe ───────────────────────────────────────────────────────────────────

// binaryHash returns the SHA-256 of the installed binary, recomputed only
// when its size or mtime changed.
func (u *unixObliReachOps) binaryHash(fi os.FileInfo) string {
	u.hashMu.Lock()
	defer u.hashMu.Unlock()
	if u.hashSum != "" && u.hashSize == fi.Size() && u.hashMtime.Equal(fi.ModTime()) {
		return u.hashSum
	}
	f, err := os.Open(u.binaryPath())
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	u.hashSum = hex.EncodeToString(h.Sum(nil))
	u.hashSize = fi.Size()
	u.hashMtime = fi.ModTime()
	return u.hashSum
}

func (u *unixObliReachOps) invalidateHash() {
	u.hashMu.Lock()
	u.hashSum = ""
	u.hashMu.Unlock()
}

func (u *unixObliReachOps) Probe(want *ObliReachDesired, deep bool) obliReachProbe {
	var p obliReachProbe
	fi, err := os.Stat(u.binaryPath())
	if err == nil && fi.Mode().IsRegular() {
		p.Installed = true
		p.ServiceExists = true
		p.Hash = u.binaryHash(fi)
		if want != nil && want.SHA256 != "" && p.Hash == want.SHA256 {
			p.Version = want.Version
		} else if data, err := os.ReadFile(filepath.Join(obliReachConfigDirUnix, "version.txt")); err == nil {
			p.Version = truncateStr(strings.TrimSpace(string(data)), 32)
		}
	}
	p.Running = len(u.findPIDs(deep)) > 0
	return p
}

// ── Process tracking ────────────────────────────────────────────────────────

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func isObliReachName(name string) bool {
	return strings.HasPrefix(filepath.Base(name), obliReachProcessTag)
}

// isZombieLinux: a dead child nobody reaped yet still answers kill(pid, 0);
// /proc/<pid>/stat says Z (zombie) or X (dead). Linux only; false elsewhere.
func isZombieLinux(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	state := s[i+2]
	return state == 'Z' || state == 'X'
}

// isObliReachPID checks the pid really is ObliReach (pid reuse) and alive
// (a zombie must not count as a running ObliReach).
func isObliReachPID(pid int) bool {
	if runtime.GOOS == "linux" {
		if isZombieLinux(pid) {
			return false
		}
		if target, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			return isObliReachName(strings.TrimSuffix(target, " (deleted)"))
		}
	}
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}
	name, err := p.Name()
	return err == nil && isObliReachName(name)
}

func (u *unixObliReachOps) readPidFile() int {
	data, err := os.ReadFile(u.pidFile())
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

// findPIDs returns the running ObliReach processes: the pidfile one, plus a
// process-table scan when scan=true (catches instances started by an older
// install_oblireach, or a lost pidfile).
func (u *unixObliReachOps) findPIDs(scan bool) []int {
	set := map[int]bool{}
	if pid := u.readPidFile(); pidAlive(pid) && isObliReachPID(pid) {
		set[pid] = true
	}
	if scan {
		if procs, err := process.Processes(); err == nil {
			self := os.Getpid()
			for _, p := range procs {
				if int(p.Pid) == self || set[int(p.Pid)] {
					continue
				}
				if name, err := p.Name(); err == nil && isObliReachName(name) {
					set[int(p.Pid)] = true
				}
			}
		}
	}
	pids := make([]int, 0, len(set))
	for pid := range set {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids
}

// stopLocked: SIGTERM, wait up to 5 s, SIGKILL the survivors.
func (u *unixObliReachOps) stopLocked(scan bool) bool {
	pids := u.findPIDs(scan)
	if len(pids) == 0 {
		_ = os.Remove(u.pidFile())
		return false
	}
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(obliReachStopTimeout)
	for time.Now().Before(deadline) {
		alive := false
		for _, pid := range pids {
			if pidAlive(pid) && isObliReachPID(pid) {
				alive = true
				break
			}
		}
		if !alive {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, pid := range pids {
		if pidAlive(pid) && isObliReachPID(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	_ = os.Remove(u.pidFile())
	log.Printf("oblireach: stopped ObliReach (pids %v)", pids)
	return true
}

func (u *unixObliReachOps) Busy(p obliReachProbe) string { return "" }

// ── Staging / install ───────────────────────────────────────────────────────

// Stage downloads next to the binary (same filesystem → atomic rename).
func (u *unixObliReachOps) Stage(file string) (obliReachStage, error) {
	dir := obliReachInstallDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return obliReachStage{}, err
	}
	_ = os.Chmod(dir, 0755) // never group/world-writable
	return obliReachStage{Path: filepath.Join(dir, ".oblireach-agent."+randomHex(8)+".tmp")}, nil
}

func (u *unixObliReachOps) FinishStage(s obliReachStage, keepLogs bool) {
	if s.Path != "" {
		_ = os.Remove(s.Path) // already renamed away on success
	}
}

func (u *unixObliReachOps) DiscardStaging(dir string) {}

func (u *unixObliReachOps) VerifySignature(path string) error {
	return verifyObliReachSigner(path) // no-op outside Windows (hash-only)
}

func (u *unixObliReachOps) Install(path string, want *ObliReachDesired, p obliReachProbe, uninstallFirst bool, srv obliReachServer) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopLocked(true)
	if err := os.Chmod(path, 0755); err != nil {
		return orErr("install_failed", "chmod: %v", err)
	}
	if err := os.Rename(path, u.binaryPath()); err != nil {
		return orErr("install_failed", "replace binary: %v", err)
	}
	u.invalidateHash()
	if err := ensureObliReachUnixConfig(srv); err != nil {
		log.Printf("oblireach: could not write %s/config.json: %v", obliReachConfigDirUnix, err)
	}
	return nil
}

// ensureObliReachUnixConfig writes ObliReach's config.json (mode 0600) with the
// server URL + API key of this agent, so it can be launched without the key
// on its command line. Other fields ObliReach stores are preserved; its own
// later saves keep the file mode.
func ensureObliReachUnixConfig(srv obliReachServer) error {
	if srv.URL == "" || srv.APIKey == "" {
		return nil
	}
	if err := os.MkdirAll(obliReachConfigDirUnix, 0755); err != nil {
		return err
	}
	path := filepath.Join(obliReachConfigDirUnix, "config.json")
	cfg := map[string]interface{}{}
	existed := false
	if data, err := os.ReadFile(path); err == nil {
		existed = true
		_ = json.Unmarshal(data, &cfg)
	}
	changed := !existed
	if v, _ := cfg["serverUrl"].(string); v != srv.URL {
		cfg["serverUrl"] = srv.URL
		changed = true
	}
	if v, _ := cfg["apiKey"].(string); v != srv.APIKey {
		cfg["apiKey"] = srv.APIKey
		changed = true
	}
	if _, ok := cfg["deviceUuid"]; !ok {
		cfg["deviceUuid"] = "" // ObliReach resolves the hardware UUID itself
		changed = true
	}
	if !changed {
		return os.Chmod(path, 0600)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp-" + randomHex(4)
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ── Start / stop ────────────────────────────────────────────────────────────

func (u *unixObliReachOps) Start(srv obliReachServer) error {
	if IsPrivacyMode() {
		return nil // last-moment guard: never start ObliReach under privacy mode
	}
	u.mu.Lock()
	if len(u.findPIDs(true)) > 0 {
		u.mu.Unlock()
		return nil
	}
	bin := u.binaryPath()
	if _, err := os.Stat(bin); err != nil {
		u.mu.Unlock()
		return orErr("start_failed", "binary missing: %v", err)
	}
	if err := ensureObliReachUnixConfig(srv); err != nil {
		log.Printf("oblireach: could not write %s/config.json: %v", obliReachConfigDirUnix, err)
	}
	cmd := exec.Command(bin) // no --url/--key: config.json carries them
	cmd.Dir = filepath.Dir(bin)
	cmd.SysProcAttr = detachedProc()
	env := os.Environ()
	if os.Getenv("DISPLAY") == "" && runtime.GOOS == "linux" {
		if d := firstX11Display(); d != "" {
			env = append(env, "DISPLAY="+d)
		}
	}
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		u.mu.Unlock()
		return orErr("start_failed", "%v", err)
	}
	pid := cmd.Process.Pid
	_ = os.MkdirAll(configDir, 0755)
	_ = os.WriteFile(u.pidFile(), []byte(strconv.Itoa(pid)), 0644)
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }() // reap: no zombie
	u.mu.Unlock()
	log.Printf("oblireach: launched %s (pid %d)", bin, pid)

	select {
	case <-exited:
		_ = os.Remove(u.pidFile())
		return orErr("exited_immediately", "ObliReach exited within %s (see %s/oblireach.log)", obliReachConfirmDelay, obliReachConfigDirUnix)
	case <-time.After(obliReachConfirmDelay):
		return nil
	}
}

func (u *unixObliReachOps) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopLocked(true)
}

func (u *unixObliReachOps) EnforceStopped(deep bool) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	// Re-read privacy mode right before acting: the caller's check may
	// predate a switch to OFF (PrivacyReleased is starting / installing it).
	if !IsPrivacyMode() {
		return false
	}
	return u.stopLocked(deep)
}
