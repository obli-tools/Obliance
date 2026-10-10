//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// ── PowerShell version probe (fake runner) ────────────────────────────────────

func withFakePSRunner(t *testing.T, out string, err error) *int {
	t.Helper()
	calls := 0
	saved := psVersionRunner
	psVersionRunner = func(_ context.Context, script string) ([]byte, error) {
		calls++
		if script != psVersionScript {
			t.Errorf("unexpected script %q", script)
		}
		return []byte(out), err
	}
	resetPSVersionCache()
	t.Cleanup(func() {
		psVersionRunner = saved
		resetPSVersionCache()
	})
	return &calls
}

func TestPSVersionProbePS2(t *testing.T) {
	calls := withFakePSRunner(t, "2.0\r\n", nil)
	if v := powerShellVersion(); v != "2.0" {
		t.Fatalf("version %q", v)
	}
	if psAtLeast(3) || !psAtLeast(2) || psMajorVersion() != 2 {
		t.Fatalf("PS 2.0 branches wrong")
	}
	if *calls != 1 {
		t.Fatalf("probe not cached: %d calls", *calls)
	}
}

func TestPSVersionProbePS51(t *testing.T) {
	withFakePSRunner(t, "5.1.14393.7259\r\n", nil)
	if !psAtLeast(3) || !psAtLeast(5) || psAtLeast(6) {
		t.Fatalf("PS 5.1 branches wrong")
	}
	if v := powerShellVersionNoWait(); v != "5.1.14393.7259" {
		t.Fatalf("cached version %q", v)
	}
}

func TestPSVersionProbeFailureIsUnknownAndThrottled(t *testing.T) {
	calls := withFakePSRunner(t, "", errors.New("exec: powershell.exe: not found"))
	if psAtLeast(2) || powerShellVersion() != "" {
		t.Fatalf("a failed probe must read as unknown (PS 2.0-safe path)")
	}
	_ = psMajorVersion()
	if *calls != 1 {
		t.Fatalf("failed probe retried immediately: %d calls", *calls)
	}
}

// ── Services (native SCM) ─────────────────────────────────────────────────────

func TestServiceStateNames(t *testing.T) {
	if strings.ToLower(win32ServiceStateName(windows.SERVICE_START_PENDING)) != "start pending" ||
		strings.ToLower(win32ServiceStateName(windows.SERVICE_RUNNING)) != "running" ||
		win32ServiceStateName(99) != "Unknown" {
		t.Fatalf("Win32_Service State names")
	}
	for st, want := range map[uint32]string{
		windows.SERVICE_AUTO_START: "Auto", windows.SERVICE_DEMAND_START: "Manual",
		windows.SERVICE_DISABLED: "Disabled", windows.SERVICE_BOOT_START: "Boot", windows.SERVICE_SYSTEM_START: "System",
	} {
		if got := win32ServiceStartModeName(st); got != want {
			t.Errorf("StartMode %d: %q want %q", st, got, want)
		}
	}
	if psServiceStartTypeName(windows.SERVICE_AUTO_START) != "Automatic" ||
		psServiceStatusName(windows.SERVICE_STOPPED) != "Stopped" ||
		psServiceStatusName(windows.SERVICE_STOP_PENDING) != "StopPending" {
		t.Fatalf("Get-Service names")
	}
	// Same JSON as `Start-Service -PassThru | Select-Object Name,Status | ConvertTo-Json -Compress`.
	if got := serviceControlOutput("Spooler", windows.SERVICE_RUNNING); got != `{"Name":"Spooler","Status":4}` {
		t.Fatalf("control output %s", got)
	}
}

func TestListServicesNative(t *testing.T) {
	svcs, err := listServicesNative()
	if err != nil {
		t.Fatalf("listServicesNative: %v", err)
	}
	if len(svcs) < 20 {
		t.Fatalf("only %d services", len(svcs))
	}
	var rpc *ServiceInfo
	seen := map[string]bool{}
	for i := range svcs {
		s := &svcs[i]
		if s.Name == "" || s.Status == "" {
			t.Fatalf("empty field in %+v", *s)
		}
		if s.Status != strings.ToLower(s.Status) || s.StartType != strings.ToLower(s.StartType) {
			t.Fatalf("not lower-cased: %+v", *s)
		}
		if seen[strings.ToLower(s.Name)] {
			t.Fatalf("duplicate service %q", s.Name)
		}
		seen[strings.ToLower(s.Name)] = true
		if strings.EqualFold(s.Name, "RpcSs") {
			rpc = s
		}
	}
	if rpc == nil || rpc.Status != "running" || rpc.StartType != "auto" || rpc.RunAsUser == "" || rpc.DisplayName == "" {
		t.Fatalf("RpcSs: %+v", rpc)
	}
	// The JSON shape posted to the server is unchanged.
	b, _ := json.Marshal(svcs[0])
	if !regexp.MustCompile(`^\{"name":".+","displayName":".*","status":"[a-z ]+"`).Match(b) {
		t.Fatalf("shape %s", b)
	}
}

func TestServiceStartTypeAndStatus(t *testing.T) {
	st, status, found, err := serviceStartTypeAndStatus("rpcss") // case-insensitive like Get-Service
	if err != nil || !found || st != "Automatic" || status != "Running" {
		t.Fatalf("RpcSs: %q %q found=%v err=%v", st, status, found, err)
	}
	_, _, found, err = serviceStartTypeAndStatus("ObliNoSuchService-42")
	if err != nil || found {
		t.Fatalf("missing service: found=%v err=%v", found, err)
	}
}

func TestStartServiceNativeMissing(t *testing.T) {
	if _, err := startServiceNative("ObliNoSuchService-42"); err == nil || !strings.Contains(err.Error(), "Cannot find any service") {
		t.Fatalf("err=%v", err)
	}
}

// ── Firewall (registry) ───────────────────────────────────────────────────────

func TestCountEnabledFirewallProfiles(t *testing.T) {
	type v struct {
		val     uint32
		present bool
		err     error
	}
	run := func(m map[string]v) (int, bool) {
		return countEnabledFirewallProfiles(func(p string) (uint32, bool, error) {
			x, ok := m[p]
			if !ok {
				return 0, false, errors.New("no key")
			}
			return x.val, x.present, x.err
		})
	}
	if n, ok := run(map[string]v{"DomainProfile": {1, true, nil}, "StandardProfile": {1, true, nil}, "PublicProfile": {1, true, nil}}); n != 3 || !ok {
		t.Fatalf("all on: %d %v", n, ok)
	}
	if n, ok := run(map[string]v{"DomainProfile": {0, true, nil}, "StandardProfile": {1, true, nil}, "PublicProfile": {0, false, nil}}); n != 2 || !ok {
		t.Fatalf("mixed (absent value = on): %d %v", n, ok)
	}
	if n, ok := run(map[string]v{}); n != 0 || ok {
		t.Fatalf("unreadable: %d %v", n, ok)
	}
	if s := windowsFirewallStatus(); !regexp.MustCompile(`^profiles_enabled:[0-3]$`).MatchString(s) {
		t.Fatalf("live status %q", s)
	}
}

// ── Orphan cleanup (Toolhelp32) ───────────────────────────────────────────────

func TestFindOrphanedObliScriptsRuns(t *testing.T) {
	// No wscript.exe of ours runs on a build machine: nothing to kill, and
	// the enumeration must not fail.
	if pids := findOrphanedObliScripts(); len(pids) != 0 {
		t.Fatalf("unexpected orphans %v", pids)
	}
}

// ── Self-update MSI selection on this (Windows 10+) host ──────────────────────

func TestCurrentAgentMSINameOnWindows10Plus(t *testing.T) {
	major, _, _ := windowsOSVersion()
	if major < 10 {
		t.Skipf("host is Windows NT %d.x", major)
	}
	saved := buildFlavor
	defer func() { buildFlavor = saved }()
	buildFlavor = ""
	want := agentMSIName(runtime.GOARCH, false)
	if osNeedsNT6Build() || currentAgentMSIName() != want {
		t.Fatalf("modern build on Windows 10+: %q want %q", currentAgentMSIName(), want)
	}
	buildFlavor = buildFlavorNT6 // an nt6 binary never leaves the nt6 line
	if got := currentAgentMSIName(); got != agentMSIName(runtime.GOARCH, true) {
		t.Fatalf("nt6 build: %q", got)
	}
}
