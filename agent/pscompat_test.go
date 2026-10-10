package main

import (
	"reflect"
	"strings"
	"testing"
)

// PowerShell 3+ constructs that break on Windows PowerShell 2.0 (Windows 7 /
// Server 2008 R2). The PS-2.0 fallback scripts must contain none.
var ps3OnlyConstructs = []string{
	"::new(", "ConvertTo-Json", "ConvertFrom-Json", "Get-CimInstance",
	"[PSCustomObject]", "[ordered]", "$PSItem", ".Where(", ".ForEach(",
	" -in ", " -notin ",
}

func TestPSCompatScriptsArePS2Safe(t *testing.T) {
	scripts := map[string]string{
		"psUTF8Prefix":         psUTF8Prefix,
		"psVersionScript":      psVersionScript,
		"securityCenterScript": securityCenterScript,
		"bitLockerWMIScript":   bitLockerWMIScript,
	}
	for name, s := range scripts {
		for _, c := range ps3OnlyConstructs {
			if strings.Contains(s, c) {
				t.Errorf("%s uses %q (PowerShell 3+)", name, c)
			}
		}
	}
	// The UTF-8 prefix must still force a BOM-less UTF-8 encoding.
	if !strings.Contains(psUTF8Prefix, "New-Object System.Text.UTF8Encoding $false") ||
		!strings.HasSuffix(psUTF8Prefix, ";") {
		t.Fatalf("unexpected UTF-8 prefix %q", psUTF8Prefix)
	}
}

func TestParsePSVersion(t *testing.T) {
	cases := []struct {
		in    string
		ver   string
		major int
	}{
		{"2.0\r\n", "2.0", 2},
		{utf8BOM + "5.1.17763.6414\r\n", "5.1.17763.6414", 5},
		{"\r\n\r\n3.0\r\n", "3.0", 3},
		{"4.0", "4.0", 4},
		{"", "", 0},
		{"garbage", "", 0},
		{"5", "", 0},
		{"x.1", "", 0},
		{"5.1.beta", "", 0},
		{"The term 'x' is not recognized", "", 0},
	}
	for _, c := range cases {
		ver, major := parsePSVersion(c.in)
		if ver != c.ver || major != c.major {
			t.Errorf("parsePSVersion(%q) = %q,%d want %q,%d", c.in, ver, major, c.ver, c.major)
		}
	}
}

func TestParseSecurityCenterOutput(t *testing.T) {
	av, fw := parseSecurityCenterOutput(utf8BOM + "AV=ESET Security\r\nFW=ESET Firewall\r\n")
	if av != "ESET Security" || fw != "ESET Firewall" {
		t.Fatalf("got %q %q", av, fw)
	}
	av, fw = parseSecurityCenterOutput("FW=Sophos Firewall\r\n")
	if av != "" || fw != "Sophos Firewall" {
		t.Fatalf("got %q %q", av, fw)
	}
	// Errors / noise / empty → nothing.
	av, fw = parseSecurityCenterOutput("Get-WmiObject : Invalid namespace\r\nAV=\r\n")
	if av != "" || fw != "" {
		t.Fatalf("got %q %q", av, fw)
	}
}

func TestParseBitLockerWMIOutput(t *testing.T) {
	out := utf8BOM + "BLV|C:|1|1|100|111111-222222-333333-444444-555555-666666-777777-888888;123456-123456-123456-123456-123456-123456-123456-123456\r\n" +
		"BLV|D:|0|0|0|\r\n" +
		"BLV|\\\\?\\Volume{0b1c2d3e-0000-0000-0000-100000000000}\\|2|0|42|\r\n" +
		"BLV|E:|-1|-1|0|\r\n" +
		"BLV|F:|4|2|oops|\r\n" +
		"some warning line\r\n" +
		"BLV||1|1|100|\r\n" + // no mount point: skipped
		"BLV|G:|1\r\n" // truncated: skipped
	got := parseBitLockerWMIOutput(out)
	want := []BitLockerVolume{
		{DriveLetter: "C:", Status: "FullyEncrypted", ProtectionStatus: "On", EncryptionPercentage: 100,
			RecoveryKeys: []string{"111111-222222-333333-444444-555555-666666-777777-888888", "123456-123456-123456-123456-123456-123456-123456-123456"}},
		{DriveLetter: "D:", Status: "FullyDecrypted", ProtectionStatus: "Off", EncryptionPercentage: 0, RecoveryKeys: []string{}},
		{DriveLetter: `\\?\Volume{0b1c2d3e-0000-0000-0000-100000000000}\`, Status: "EncryptionInProgress", ProtectionStatus: "Off", EncryptionPercentage: 42, RecoveryKeys: []string{}},
		{DriveLetter: "E:", Status: "Unknown", ProtectionStatus: "Unknown", EncryptionPercentage: 0, RecoveryKeys: []string{}},
		{DriveLetter: "F:", Status: "EncryptionPaused", ProtectionStatus: "Unknown", EncryptionPercentage: 0, RecoveryKeys: []string{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}
	if v := parseBitLockerWMIOutput(""); v != nil {
		t.Fatalf("empty output: %#v", v)
	}
	// Status names are Get-BitLockerVolume's.
	for conv, name := range map[int]string{0: "FullyDecrypted", 1: "FullyEncrypted", 2: "EncryptionInProgress",
		3: "DecryptionInProgress", 4: "EncryptionPaused", 5: "DecryptionPaused", 9: "Unknown"} {
		if got := bitLockerVolumeStatusName(conv); got != name {
			t.Errorf("conv %d: %q want %q", conv, got, name)
		}
	}
}

func TestIsOrphanedObliScript(t *testing.T) {
	cases := []struct {
		name, cmd string
		want      bool
	}{
		{"wscript.exe", `"C:\Windows\System32\wscript.exe" C:\ProgramData\OblianceAgent\wu.vbs`, true},
		{"WScript.exe", `wscript.exe //B C:\Temp\OBLIANCE-update.vbs`, true},
		{"wscript.exe", `wscript.exe C:\Users\bob\login.vbs`, false},
		{"cscript.exe", `cscript.exe C:\ProgramData\OblianceAgent\wu.vbs`, false},
		{"obliance-agent.exe", `obliance-agent.exe`, false},
	}
	for _, c := range cases {
		if got := isOrphanedObliScript(c.name, c.cmd); got != c.want {
			t.Errorf("%s %q: %v want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestAgentMSIName(t *testing.T) {
	cases := []struct {
		arch string
		nt6  bool
		want string
	}{
		{"amd64", false, "obliance-agent.msi"},
		{"386", false, "obliance-agent-x86.msi"},
		{"amd64", true, "obliance-agent-nt6.msi"},
		{"386", true, "obliance-agent-nt6-x86.msi"},
	}
	for _, c := range cases {
		if got := agentMSIName(c.arch, c.nt6); got != c.want {
			t.Errorf("%s nt6=%v: %q want %q", c.arch, c.nt6, got, c.want)
		}
	}
	saved := buildFlavor
	defer func() { buildFlavor = saved }()
	buildFlavor = ""
	if isNT6Build() || agentBuildName() != "modern" {
		t.Fatalf("default build must be modern")
	}
	buildFlavor = "nt6"
	if !isNT6Build() || agentBuildName() != "nt6" {
		t.Fatalf("nt6 build not detected")
	}
}
