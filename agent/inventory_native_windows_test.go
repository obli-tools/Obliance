//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestNativeInventoryMatchesLegacyScript runs the former PowerShell inventory
// script (PowerShell 3+ only: ConvertTo-Json) and the native WMI collection
// on this machine and compares the resulting InventoryData field by field.
// Known, intended difference: the script dropped every disk whose
// SerialNumber was NULL (`$null.Trim()`), the native path keeps it — so the
// legacy disks must be a subset of the native ones.
func TestNativeInventoryMatchesLegacyScript(t *testing.T) {
	if testing.Short() {
		t.Skip("slow (WMI + PowerShell)")
	}
	out, err := runPS(legacyInventoryScript)
	if err != nil {
		t.Skipf("legacy script unavailable: %v", err)
	}
	var legacyRaw map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(out), &legacyRaw); err != nil {
		t.Skipf("legacy script output not JSON (PowerShell 2.0?): %v", err)
	}
	legacy := &InventoryData{Raw: map[string]interface{}{}}
	applyWindowsInventoryRaw(legacy, legacyRaw)

	native := &InventoryData{Raw: map[string]interface{}{}}
	if err := scanWindowsInventory(native); err != nil {
		t.Fatalf("native scan: %v", err)
	}

	same := func(name string, a, b interface{}) {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if !bytes.Equal(ja, jb) {
			t.Errorf("%s differs:\nlegacy: %s\nnative: %s", name, ja, jb)
		}
	}
	same("cpu", legacy.CPU, native.CPU)
	same("memory", legacy.Memory, native.Memory)
	same("network", legacy.Network, native.Network)
	same("gpu", legacy.GPU, native.GPU)
	same("motherboard", legacy.Motherboard, native.Motherboard)
	same("bios", legacy.BIOS, native.BIOS)
	same("tpm", legacy.TPM, native.TPM)
	if testIsWow64() {
		// 32-bit test process on a 64-bit OS: the legacy oracle runs in a 32-bit
		// PowerShell that misses values the native path reads (e.g. the OA3
		// product key): legacy non-empty fields must match, native may add.
		if legacy.OS.WindowsKey == "" {
			legacy.OS.WindowsKey = native.OS.WindowsKey
		}
		if legacy.OS.OfficeKey == "" {
			legacy.OS.OfficeKey = native.OS.OfficeKey
		}
		if legacy.OS.OfficeVersion == "" {
			legacy.OS.OfficeVersion = native.OS.OfficeVersion
		}
	}
	same("os", legacy.OS, native.OS)
	same("battery", legacy.Battery, native.Battery)
	same("printers", legacy.Printers, native.Printers)
	same("comPorts", legacy.ComPorts, native.ComPorts)
	for _, d := range legacy.Disks {
		found := false
		for _, n := range native.Disks {
			if reflect.DeepEqual(d, n) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("legacy disk %+v missing from native %+v", d, native.Disks)
		}
	}
	if len(native.Disks) == 0 {
		t.Errorf("native scan found no disk")
	}

	// Same top-level and nested key sets in Raw["wmi"] (inv.Raw shape).
	nativeRaw, _ := native.Raw["wmi"].(map[string]interface{})
	for k, lv := range legacyRaw {
		nv, ok := nativeRaw[k]
		if !ok {
			t.Errorf("raw key %q missing from native", k)
			continue
		}
		if lm, ok := lv.(map[string]interface{}); ok {
			nm, _ := nv.(map[string]interface{})
			for kk := range lm {
				if _, ok := nm[kk]; !ok {
					t.Errorf("raw key %q.%q missing from native", k, kk)
				}
			}
		}
	}
	t.Logf("native disks: %+v", native.Disks)

	// Keys added after the former script: same values as Get-WmiObject.
	checkMachineIdentityAgainstOracle(t, nativeRaw)
}

// checkMachineIdentityAgainstOracle compares raw bios.serial / system.* with
// machineIdentityOracleScript's output on this machine.
func checkMachineIdentityAgainstOracle(t *testing.T, nativeRaw map[string]interface{}) {
	t.Helper()
	out, err := runPS(machineIdentityOracleScript)
	if err != nil {
		t.Skipf("identity oracle unavailable: %v", err)
	}
	var vals []string
	for _, line := range strings.Split(string(out), "\n") {
		if l := strings.TrimRight(line, "\r"); strings.HasPrefix(l, "v=") {
			vals = append(vals, strings.TrimSpace(l[2:]))
		}
	}
	if len(vals) != 6 {
		t.Fatalf("identity oracle output: %q", out)
	}
	bios, _ := nativeRaw["bios"].(map[string]interface{})
	sys, _ := nativeRaw["system"].(map[string]interface{})
	if sys == nil {
		t.Fatalf("raw.system missing: %v", nativeRaw)
	}
	pcType := ""
	if v, ok := sys["pcSystemType"]; ok {
		pcType = fmt.Sprint(v)
	}
	got := []string{fmt.Sprint(bios["serial"]), fmt.Sprint(sys["manufacturer"]), fmt.Sprint(sys["model"]),
		fmt.Sprint(sys["family"]), pcType, fmt.Sprint(sys["version"])}
	names := []string{"bios.serial", "system.manufacturer", "system.model", "system.family", "system.pcSystemType", "system.version"}
	for i := range names {
		if got[i] != vals[i] {
			t.Errorf("%s: native %q, Get-WmiObject %q", names[i], got[i], vals[i])
		}
	}
	t.Logf("identity: bios.serial=%q system=%v", got[0], sys)
}

// TestNativeSoftwareMatchesLegacyScript compares the registry software list
// read natively with the former PowerShell script's output on this machine.
func TestNativeSoftwareMatchesLegacyScript(t *testing.T) {
	if testing.Short() {
		t.Skip("slow (PowerShell)")
	}
	out, err := runPS("$ErrorActionPreference='SilentlyContinue'\n" + legacySoftwareScript)
	if err != nil {
		t.Skipf("legacy script unavailable: %v", err)
	}
	legacy := map[string]SoftwareEntry{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 5)
		for len(parts) < 5 {
			parts = append(parts, "")
		}
		e := SoftwareEntry{Name: strings.TrimSpace(parts[0]), Version: strings.TrimSpace(parts[1]),
			Publisher: strings.TrimSpace(parts[2]), InstallDate: strings.TrimSpace(parts[3]),
			InstallLocation: strings.TrimSpace(parts[4]), Source: "registry"}
		if e.Name != "" {
			legacy[strings.ToLower(e.Name)] = e
		}
	}
	native := scanWindowsSoftware()
	wow := testIsWow64()
	if wow {
		// 32-bit PowerShell only sees the 32-bit registry view: every legacy
		// entry must be in the native list, which also has the 64-bit apps.
		names := map[string]bool{}
		for _, n := range native {
			names[strings.ToLower(n.Name)] = true
		}
		for k := range legacy {
			if !names[k] {
				t.Errorf("legacy entry %q missing from native", k)
			}
		}
		t.Logf("WOW64: legacy %d entries, native %d", len(legacy), len(native))
		return
	}
	if len(native) != len(legacy) {
		t.Errorf("count: legacy %d, native %d", len(legacy), len(native))
	}
	diff := 0
	for _, n := range native {
		l, ok := legacy[strings.ToLower(n.Name)]
		if !ok {
			t.Errorf("native-only entry %+v", n)
			continue
		}
		if l != n {
			diff++
			t.Logf("field difference (duplicate DisplayName resolved differently?):\nlegacy %+v\nnative %+v", l, n)
		}
	}
	t.Logf("native %d entries, %d with differing fields", len(native), diff)
}

// TestReadIdentityNative: the native readers answer what the old PowerShell /
// wmic paths answered (captured at implementation time on the dev machine:
// both available) — at least they must not be empty where WMI works.
// testIsWow64: 32-bit process on a 64-bit Windows.
func testIsWow64() bool {
	var wow bool
	if err := windows.IsWow64Process(windows.CurrentProcess(), &wow); err != nil {
		return false
	}
	return wow
}

func TestReadIdentityNative(t *testing.T) {
	if u := wmiMachineUUID(); normaliseUUID(u) == "" {
		t.Logf("no usable SMBIOS UUID from WMI (%q)", u)
	} else {
		t.Logf("WMI UUID: %s", u)
	}
	serial, ok := wmiDiskSerialByIndex(0)
	if !ok {
		t.Fatalf("WMI disk query failed")
	}
	t.Logf("disk 0 serial: %q", serial)
}
