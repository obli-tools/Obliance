//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCollectNT6PrereqsLive runs the real checks on this machine (whatever its
// version): no panic, coherent values on Windows 10+ (everything native).
func TestCollectNT6PrereqsLive(t *testing.T) {
	p := collectNT6Prereqs()
	t.Logf("prereqs: %+v sp1=%v", *p, p.SP1)
	major, _, _ := windowsOSVersion()
	if major >= 10 {
		if !p.SHA2Signing || !p.KB2533623 || p.SP1 != nil {
			t.Errorf("Windows 10+: %+v", *p)
		}
		if nt6PrereqsForPush() != nil {
			t.Error("prereqs must be omitted on Windows 10+")
		}
		if sha2SigningMissing() {
			t.Error("sha2SigningMissing on Windows 10+")
		}
	}
}

// TestPSTLS12PreambleRuns: the preamble is valid PowerShell and turns Tls12 on
// (run with -File like run_script does).
func TestPSTLS12PreambleRuns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.ps1")
	script := psTLS12Preamble + "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3 -bor [Net.SecurityProtocolType]::Tls\n" +
		psTLS12Preamble + "Write-Output ([Net.ServicePointManager]::SecurityProtocol.ToString())\nexit 7\n"
	if err := os.WriteFile(p, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := newCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", p).Output()
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "Tls12") || !strings.Contains(got, "Tls") {
		t.Fatalf("SecurityProtocol = %q (err %v)", got, err)
	}
	if err == nil {
		t.Fatal("exit code of the script must be kept (want 7)")
	}
}
