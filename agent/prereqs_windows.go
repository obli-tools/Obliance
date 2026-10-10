//go:build windows

package main

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// prereqsTTL: the checks are cheap but their inputs only change with updates
// (often followed by a reboot, which restarts the agent anyway).
const prereqsTTL = time.Hour

var (
	prereqsMu     sync.Mutex
	prereqsCached *NT6Prereqs
	prereqsAt     time.Time
)

// nt6PrereqsForPush returns the prerequisites on Windows < 10, nil elsewhere
// (the field is then omitted from the push body). wmfVersion is refreshed on
// every call (non-blocking, cached by ps_windows.go).
func nt6PrereqsForPush() *NT6Prereqs {
	if !osNeedsNT6Build() {
		return nil
	}
	p := nt6Prereqs()
	cp := *p
	cp.WMFVersion = powerShellVersionNoWait()
	return &cp
}

// nt6Prereqs returns the cached prerequisites (recomputed after prereqsTTL).
func nt6Prereqs() *NT6Prereqs {
	prereqsMu.Lock()
	defer prereqsMu.Unlock()
	if prereqsCached != nil && time.Since(prereqsAt) < prereqsTTL {
		return prereqsCached
	}
	prereqsCached = collectNT6Prereqs()
	prereqsAt = time.Now()
	return prereqsCached
}

func collectNT6Prereqs() *NT6Prereqs {
	major, minor, build := windowsOSVersion()
	p := &NT6Prereqs{}
	if major == 6 && minor == 1 {
		sp1 := build >= 7601
		p.SP1 = &sp1
	}
	p.SHA2KBs = installedPackagesKBs(sha2SigningKBs)
	p.SHA2Signing = sha2SigningSupported(major, minor, p.SHA2KBs)
	p.KB2533623 = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetDefaultDllDirectories").Find() == nil
	p.TLS12Schannel = readTLS12ClientEnabled(major, minor)
	p.DotNet4x = readDotNet4Version()
	return p
}

// installedPackagesKBs returns which of kbs have a "Package_for_<KB>~" entry
// in the Component Based Servicing store (one subkey-name listing).
func installedPackagesKBs(kbs []string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`,
		registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var found []string
	for _, kb := range kbs {
		prefix := strings.ToLower("Package_for_" + kb + "~")
		for _, n := range names {
			if strings.HasPrefix(strings.ToLower(n), prefix) {
				found = append(found, kb)
				break
			}
		}
	}
	return found
}

func regDWORDPtr(k registry.Key, name string) *uint64 {
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return nil
	}
	return &v
}

func readTLS12ClientEnabled(major, minor uint32) bool {
	var enabled, disabledByDefault *uint64
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client`,
		registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		enabled = regDWORDPtr(k, "Enabled")
		disabledByDefault = regDWORDPtr(k, "DisabledByDefault")
		k.Close()
	}
	return tls12ClientEnabled(major, minor, enabled, disabledByDefault)
}

func readDotNet4Version() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	rel, _, err := k.GetIntegerValue("Release")
	if err != nil {
		rel = 0
	}
	return dotNet4VersionFromRelease(rel, true)
}

// sha2SigningMissing: Windows 7 / 2008 R2 without KB4474419 / KB3033929
// (false on 6.2+ and on Windows 10+). Swappable by tests.
var sha2SigningMissing = func() bool {
	if !osNeedsNT6Build() {
		return false
	}
	return !nt6Prereqs().SHA2Signing
}
