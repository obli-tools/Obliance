//go:build windows

package main

// Windows OS actions of the ObliReach manager (see oblireach_manager.go):
// probe through the Windows Installer API (UpgradeCode → ProductCode +
// version) and the SCM, install/uninstall through msiexec from a private
// staging folder (SYSTEM + Administrators only), start through the SCM.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	obliReachServiceName = "OblireachAgent"
	// UpgradeCode of Oblireach's agent/installer/product.wxs — stable across
	// versions (the ProductCode changes with every build).
	obliReachUpgradeCode = "{C6D7E8F9-A0B1-2345-CDEF-012345678902}"
	obliReachMsiTimeout  = 10 * time.Minute
	// Protected DACL: SYSTEM + BUILTIN\Administrators full control, nothing
	// inherited — a local user cannot swap the MSI between verification and
	// msiexec.
	obliReachStagingSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// A service stuck in a *_PENDING state stops counting as "busy" after this.
	obliReachPendingCap = 10 * time.Minute
	// Service start type sentinel: configuration could not be read.
	obliReachStartUnknown = 0xFFFFFFFF
)

var (
	modMsi                      = windows.NewLazySystemDLL("msi.dll")
	procMsiEnumRelatedProductsW = modMsi.NewProc("MsiEnumRelatedProductsW")
	procMsiGetProductInfoW      = modMsi.NewProc("MsiGetProductInfoW")

	obliReachStagingNameRe = regexp.MustCompile(`^oblireach-staging-[0-9a-f]{16}$`)
)

type winObliReachOps struct {
	mu           sync.Mutex
	pendingSince time.Time
}

var obliReachPlatformOps obliReachOps = &winObliReachOps{}

// Unix-only privacy helper (privacy.go keeps its `sc` logic on Windows).
func obliReachUnixStop() {}

func (w *winObliReachOps) Traits() obliReachTraits {
	return obliReachTraits{
		alignByHash:       false,
		selfUpdates:       true,
		startAfterInstall: false, // the MSI's ServiceControl starts the service
		notRunningGrace:   5 * time.Minute,
	}
}

// ArtifactName: Windows 10 / 11 / Server 2016+ → oblireach-agent.msi;
// Windows 7 SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2 (NT 6.x) →
// oblireach-agent-nt6.msi (ObliReach built with Go 1.20: the modern build's
// service never starts there — MSI error 1920 → 1603, seen on a 2012 R2).
// The MSI is x64-only.
func (w *winObliReachOps) ArtifactName() string {
	major, _, _ := windowsOSVersion()
	return obliReachWindowsArtifact(runtime.GOARCH, major)
}

// RejectFile: on NT 6.x a server that ships no nt6 build (older server, or
// none in its dist) sends "" or the modern MSI → "unsupported os_too_old"
// (no install loop) instead of "bad_manifest".
func (w *winObliReachOps) RejectFile(ours, file string) string {
	major, minor, build := windowsOSVersion()
	return obliReachNT6Mismatch(ours, file, major, minor, build)
}

// Precondition: the OS generation is handled by ArtifactName (nt6 build) and
// RejectFile (server without it); the MSI is x64-only, which ArtifactName
// already covers.
func (w *winObliReachOps) Precondition(strict bool) string { return "" }

// windowsOSVersion is the real OS version (RtlGetVersion ignores the
// compatibility manifest); zeros when unavailable.
func windowsOSVersion() (major, minor, build uint32) {
	if v := windows.RtlGetVersion(); v != nil {
		return v.MajorVersion, v.MinorVersion, v.BuildNumber
	}
	return 0, 0, 0
}

// ── Probe ───────────────────────────────────────────────────────────────────

type obliReachSvcInfo struct {
	exists    bool
	state     uint32
	startType uint32
}

func queryObliReachService() obliReachSvcInfo {
	info := obliReachSvcInfo{startType: obliReachStartUnknown}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return info
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(obliReachServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		// Anything but "does not exist" (e.g. access denied) means it exists.
		info.exists = err != windows.ERROR_SERVICE_DOES_NOT_EXIST
		return info
	}
	defer windows.CloseServiceHandle(h)
	info.exists = true
	var ss windows.SERVICE_STATUS
	if windows.QueryServiceStatus(h, &ss) == nil {
		info.state = ss.CurrentState
	}
	var needed uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &needed)
	if needed > 0 && needed < 64*1024 {
		buf := make([]uint64, (needed+7)/8)
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
		if windows.QueryServiceConfig(h, cfg, needed, &needed) == nil {
			info.startType = cfg.StartType
		}
	}
	return info
}

// msiRelatedProduct returns the installed product (ProductCode, version) for
// the ObliReach UpgradeCode, or ("", "") when none is registered.
func msiRelatedProduct(upgradeCode string) (productCode, version string) {
	if procMsiEnumRelatedProductsW.Find() != nil || procMsiGetProductInfoW.Find() != nil {
		return "", ""
	}
	uc, err := windows.UTF16PtrFromString(upgradeCode)
	if err != nil {
		return "", ""
	}
	for i := uint32(0); i < 8; i++ {
		buf := make([]uint16, 39) // GUID string + NUL
		r, _, _ := procMsiEnumRelatedProductsW.Call(uintptr(unsafe.Pointer(uc)), 0, uintptr(i), uintptr(unsafe.Pointer(&buf[0])))
		if r != 0 { // ERROR_NO_MORE_ITEMS (259) or an error
			break
		}
		pc := windows.UTF16ToString(buf)
		ver := msiProductInfo(pc, "VersionString")
		if productCode == "" || obliReachVersionCmp(ver, version) > 0 {
			productCode, version = pc, ver
		}
	}
	return productCode, version
}

func msiProductInfo(product, attr string) string {
	p16, err1 := windows.UTF16PtrFromString(product)
	a16, err2 := windows.UTF16PtrFromString(attr)
	if err1 != nil || err2 != nil {
		return ""
	}
	n := uint32(64)
	for try := 0; try < 2; try++ {
		buf := make([]uint16, n)
		size := n
		r, _, _ := procMsiGetProductInfoW.Call(uintptr(unsafe.Pointer(p16)), uintptr(unsafe.Pointer(a16)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		switch r {
		case 0:
			if size > n {
				size = n
			}
			return strings.TrimSpace(windows.UTF16ToString(buf[:size]))
		case 234: // ERROR_MORE_DATA
			n = size + 1
		default:
			return ""
		}
	}
	return ""
}

func (w *winObliReachOps) Probe(want *ObliReachDesired, deep bool) obliReachProbe {
	var p obliReachProbe
	if pc, ver := msiRelatedProduct(obliReachUpgradeCode); pc != "" {
		p.Installed = true
		p.ProductCode = pc
		p.Version = ver
	}
	svc := queryObliReachService()
	p.ServiceExists = svc.exists
	p.Running = svc.state == windows.SERVICE_RUNNING
	switch svc.state {
	case windows.SERVICE_START_PENDING, windows.SERVICE_STOP_PENDING,
		windows.SERVICE_CONTINUE_PENDING, windows.SERVICE_PAUSE_PENDING:
		p.Pending = true
	}
	p.StartDisabled = svc.startType == windows.SERVICE_DISABLED
	if !p.Installed && p.ServiceExists {
		// Pre-MSI layout: only the running version is known.
		p.Version = readObliReachRunningVersion()
	}
	return p
}

// readObliReachRunningVersion reads the version ObliReach writes at start
// (C:\ProgramData\OblireachAgent\version.txt).
func readObliReachRunningVersion() string {
	pd := os.Getenv("PROGRAMDATA")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	data, err := os.ReadFile(filepath.Join(pd, "OblireachAgent", "version.txt"))
	if err != nil {
		return ""
	}
	return truncateStr(strings.TrimSpace(string(data)), 32)
}

// ── Busy ────────────────────────────────────────────────────────────────────

// msiExecuteMutexExists reports whether a Windows Installer transaction is
// running (any product: ObliReach self-update, Windows Update, …).
func msiExecuteMutexExists() bool {
	name, _ := windows.UTF16PtrFromString(`Global\_MSIExecute`)
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return err == windows.ERROR_ACCESS_DENIED
}

func (w *winObliReachOps) Busy(p obliReachProbe) string {
	if msiExecuteMutexExists() {
		return orReasonBusyMSI
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !p.Pending {
		w.pendingSince = time.Time{}
		return ""
	}
	if w.pendingSince.IsZero() {
		w.pendingSince = time.Now()
	}
	if time.Since(w.pendingSince) < obliReachPendingCap {
		return orReasonBusyMSI
	}
	return "" // stuck in a pending state: let the installer sort it out
}

// ── Staging ─────────────────────────────────────────────────────────────────

func (w *winObliReachOps) Stage(file string) (obliReachStage, error) {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return obliReachStage{}, err
	}
	sd, err := windows.SecurityDescriptorFromString(obliReachStagingSDDL)
	if err != nil {
		return obliReachStage{}, err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for i := 0; i < 5; i++ {
		// Random name + CreateDirectory (fails if it exists): a local user
		// cannot pre-create or plant this folder.
		dir := filepath.Join(configDir, "oblireach-staging-"+randomHex(8))
		d16, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return obliReachStage{}, err
		}
		err = windows.CreateDirectory(d16, sa)
		if err == nil {
			return obliReachStage{Dir: dir, Path: filepath.Join(dir, file)}, nil
		}
		if err != windows.ERROR_ALREADY_EXISTS {
			return obliReachStage{}, err
		}
	}
	return obliReachStage{}, fmt.Errorf("could not create a staging folder")
}

func (w *winObliReachOps) FinishStage(s obliReachStage, keepLogs bool) {
	if s.Path != "" {
		_ = os.Remove(s.Path)
	}
	if !keepLogs {
		w.DiscardStaging(s.Dir)
	}
}

// DiscardStaging removes a staging folder this manager created (strict name
// + location check, never anything else).
func (w *winObliReachOps) DiscardStaging(dir string) {
	if dir == "" || !strings.EqualFold(filepath.Clean(filepath.Dir(dir)), filepath.Clean(configDir)) ||
		!obliReachStagingNameRe.MatchString(filepath.Base(dir)) {
		return
	}
	_ = os.RemoveAll(dir)
}

func (w *winObliReachOps) VerifySignature(path string) error {
	return verifyObliReachSigner(path)
}

// ── Install ─────────────────────────────────────────────────────────────────

// runMsiexec runs msiexec synchronously; timedOut=true when it had to be
// killed (the Windows Installer transaction may still finish on its own).
func runMsiexec(timeout time.Duration, args ...string) (code int, timedOut bool, err error) {
	exe := "msiexec.exe"
	if root := os.Getenv("SystemRoot"); root != "" {
		exe = filepath.Join(root, "System32", "msiexec.exe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	runErr := newCmdContext(ctx, exe, args...).Run()
	if ctx.Err() == context.DeadlineExceeded {
		return -1, true, nil
	}
	if runErr == nil {
		return 0, false, nil
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		return ee.ExitCode(), false, nil
	}
	return -1, false, runErr
}

func (w *winObliReachOps) Install(path string, want *ObliReachDesired, p obliReachProbe, uninstallFirst bool, srv obliReachServer) error {
	msiMu.Lock()
	defer msiMu.Unlock()
	// Re-check under the lock: another installer may have started meanwhile.
	if msiExecuteMutexExists() {
		return &orError{Busy: orReasonBusyMSI}
	}
	if agentSelfUpdateBusy() {
		return &orError{Busy: orReasonBusyAgentUpd}
	}
	dir := filepath.Dir(path)

	if uninstallFirst && p.Installed && p.ProductCode != "" {
		// Downgrade (the MSI refuses it: MajorUpgrade DowngradeErrorMessage),
		// broken registration or repair: remove the product first.
		log.Printf("oblireach: uninstalling %s (%s) before install", p.ProductCode, p.Version)
		code, timedOut, err := runMsiexec(obliReachMsiTimeout,
			"/x", p.ProductCode, "/quiet", "/norestart", "/l*v", filepath.Join(dir, "uninstall.log"))
		switch {
		case err != nil:
			return orErr("uninstall_exit_-1", "msiexec /x: %v", err)
		case timedOut:
			return orErr("timeout", "msiexec /x did not finish within %s", obliReachMsiTimeout)
		case code == 1618:
			return &orError{Busy: orReasonBusyMSI}
		case code != 0 && code != 3010 && code != 1641 && code != 1605:
			return orErr(fmt.Sprintf("uninstall_exit_%d", code), "see %s", filepath.Join(dir, "uninstall.log"))
		}
	} else if !p.Installed && p.ServiceExists {
		// Pre-MSI layout (service created with `sc create`): the MSI's
		// ServiceInstall would fail on the existing service name.
		log.Printf("oblireach: removing the non-MSI %s service before install", obliReachServiceName)
		_ = newCmd("sc", "stop", obliReachServiceName).Run()
		time.Sleep(3 * time.Second)
		_ = newCmd("sc", "delete", obliReachServiceName).Run()
	}

	// Privacy mode may have been switched on meanwhile (while msiMu was
	// awaited, or while the product was being removed above): the MSI would
	// re-create the service in automatic start and START it — do not run it.
	if IsPrivacyMode() {
		log.Printf("oblireach: privacy mode is on — msiexec /i for ObliReach %s not run", want.Version)
		return &orError{Privacy: true}
	}

	logPath := filepath.Join(dir, "install.log")
	log.Printf("oblireach: running msiexec /i for ObliReach %s", want.Version)
	code, timedOut, err := runMsiexec(obliReachMsiTimeout,
		"/i", path,
		"SERVERURL="+srv.URL,
		"APIKEY="+srv.APIKey,
		"/quiet", "/norestart",
		"/l*v", logPath,
	)
	switch {
	case err != nil:
		return orErr("msi_exit_-1", "msiexec: %v", err)
	case timedOut:
		return orErr("timeout", "msiexec /i did not finish within %s", obliReachMsiTimeout)
	}
	switch code {
	case 0, 3010, 1641:
		return nil
	case 1618:
		return &orError{Busy: orReasonBusyMSI}
	case 1638:
		return &orError{Code: "msi_exit_1638", Detail: "another version of ObliReach is installed — next attempt uninstalls it first", ForceUninstall: true}
	}
	return orErr(fmt.Sprintf("msi_exit_%d", code), "see %s", logPath)
}

// ── Service control ─────────────────────────────────────────────────────────

func (w *winObliReachOps) Start(srv obliReachServer) error {
	if IsPrivacyMode() {
		return nil // last-moment guard: never start ObliReach under privacy mode
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return orErr("start_failed", "open SCM: %v", err)
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(obliReachServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return orErr("start_failed", "open service: %v", err)
	}
	defer windows.CloseServiceHandle(h)
	if err := windows.ChangeServiceConfig(h, windows.SERVICE_NO_CHANGE, windows.SERVICE_AUTO_START,
		windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil); err != nil {
		return orErr("start_failed", "enable service: %v", err)
	}
	if err := windows.StartService(h, 0, nil); err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		return orErr("start_failed", "%v", err)
	}
	for i := 0; i < 15; i++ {
		time.Sleep(time.Second)
		var ss windows.SERVICE_STATUS
		if windows.QueryServiceStatus(h, &ss) != nil {
			continue
		}
		switch ss.CurrentState {
		case windows.SERVICE_RUNNING:
			return nil
		case windows.SERVICE_STOPPED:
			return orErr("exited_immediately", "service stopped right after start (exit code %d)", ss.Win32ExitCode)
		}
	}
	return nil // still starting: not a failure, the next round will see
}

// Stop = the privacy-mode stop (sc stop + start= disabled).
func (w *winObliReachOps) Stop() {
	stopObliReachService()
}

func (w *winObliReachOps) EnforceStopped(deep bool) bool {
	info := queryObliReachService()
	if !info.exists {
		return false
	}
	active := info.state == windows.SERVICE_RUNNING || info.state == windows.SERVICE_START_PENDING ||
		info.state == windows.SERVICE_CONTINUE_PENDING
	autoStart := info.startType != obliReachStartUnknown && info.startType != windows.SERVICE_DISABLED
	if !active && !autoStart {
		return false
	}
	// Re-read privacy mode right before acting: the caller's check may
	// predate a switch to OFF (PrivacyReleased is starting / installing it).
	if !IsPrivacyMode() {
		return false
	}
	stopObliReachService()
	return true
}
