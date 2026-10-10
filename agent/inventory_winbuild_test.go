package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// legacyRawWS2025 is the inv.Raw["wmi"] map the former PowerShell script
// printed (ConvertTo-Json) on a Server 2025 Hyper-V VM. Product key,
// serials and network identity are placeholders. Its "disks" was []
// because both virtual disks have a NULL SerialNumber (the script's
// `$null.Trim()` dropped them): the native expectation below lists them.
const legacyRawWS2025 = `{"bios":{"date":"20250925000000.000000+000","vendor":"Microsoft Corporation","version":"Hyper-V UEFI Release v4.1"},"comPorts":[],"cpu":{"arch":64,"cores":8,"model":"AMD Ryzen Threadripper 2950X 16-Core Processor","speed":3500,"threads":16},"disks":[],"gpus":[],"mb":{"manufacturer":"Microsoft Corporation","product":"Virtual Machine","serial":"0000-1111-2222","version":"Hyper-V UEFI Release v4.1"},"memSlots":[{"manufacturer":"Microsoft Corporation","sizeMb":3968,"slot":"M0001","speedMhz":0,"type":"Unknown"},{"manufacturer":"Microsoft Corporation","sizeMb":20032,"slot":"M0002","speedMhz":0,"type":"Unknown"}],"memTotalMB":23999,"nics":[{"addrs":["10.0.0.5"],"mac":"00:15:5D:00:00:01","name":"Microsoft Hyper-V Network Adapter"}],"osDetails":{"buildNumber":"10.0.26100","displayVersion":"24H2","edition":"Microsoft Windows Server 2025 Standard","officeKey":"","officeVersion":"","windowsKey":"AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"},"printers":[{"driver":"Generic v4 Printer Driver","isDefault":false,"isNetwork":false,"isShared":false,"name":"Generic Printer","port":"Generic Printer","status":"Idle"},{"driver":"Microsoft Print To PDF","isDefault":true,"isNetwork":false,"isShared":false,"name":"Microsoft Print to PDF","port":"PORTPROMPT:","status":"Idle"}],"tpm":{"present":false}}`

// snapshotWS2025: the native WMI rows of the same machine, with the VARIANT
// types go-ole yields (uint32 -> int32, uint64 -> string, NULL -> no key).
func snapshotWS2025() winInvSnapshot {
	return winInvSnapshot{
		CPU: []wmiRow{{"Name": "AMD Ryzen Threadripper 2950X 16-Core Processor", "NumberOfCores": int32(8),
			"NumberOfLogicalProcessors": int32(16), "MaxClockSpeed": int32(3500), "AddressWidth": int32(64)}},
		Memory: []wmiRow{
			{"DeviceLocator": "M0001", "Capacity": "4160749568", "MemoryType": int32(0), "Speed": nil, "Manufacturer": "Microsoft Corporation"},
			{"DeviceLocator": "M0002", "Capacity": "21005074432", "MemoryType": int32(0), "Manufacturer": "Microsoft Corporation"},
		},
		OS: []wmiRow{{"Caption": "Microsoft Windows Server 2025 Standard", "Version": "10.0.26100", "TotalVisibleMemorySize": "24574976"}},
		Disks: []wmiRow{
			{"Model": "Disque virtuel Microsoft", "Size": "214745610240", "MediaType": "Fixed hard disk media", "InterfaceType": "SCSI"},
			{"Model": "Disque virtuel Microsoft", "Size": "268432012800", "MediaType": "Fixed hard disk media", "InterfaceType": "SCSI"},
		},
		NICs:  []wmiRow{{"Description": "Microsoft Hyper-V Network Adapter", "MACAddress": "00:15:5D:00:00:01", "IPAddress": []interface{}{"10.0.0.5"}}},
		GPUs:  []wmiRow{{"Caption": "Microsoft Hyper-V Video", "AdapterRAM": int32(0), "PNPDeviceID": `VMBUS\{DA0A7802-E377-4AAC-8E77-0558EB1073F8}\{5620E0C7-8062-4DCE-AEB7-520C7EF76171}`}},
		Board: []wmiRow{{"Manufacturer": "Microsoft Corporation", "Product": "Virtual Machine", "Version": "Hyper-V UEFI Release v4.1", "SerialNumber": "0000-1111-2222"}},
		BIOS: []wmiRow{{"Manufacturer": "Microsoft Corporation", "SMBIOSBIOSVersion": "Hyper-V UEFI Release v4.1", "ReleaseDate": "20250925000000.000000+000",
			"SerialNumber": "0000-0000-0000-0000-0000-0000-00"}},
		// Added after the former script (values of a Server 2025 Hyper-V VM).
		System:  []wmiRow{{"Manufacturer": "Microsoft Corporation", "Model": "Virtual Machine", "SystemFamily": "Virtual Machine", "PCSystemType": int32(1)}},
		Product: []wmiRow{{"Version": "Hyper-V UEFI Release v4.1"}},
		Printers: []wmiRow{
			{"Name": "Generic Printer", "DriverName": "Generic v4 Printer Driver", "PortName": "Generic Printer", "Default": false, "Network": false, "Shared": false, "PrinterStatus": int32(3)},
			{"Name": "Microsoft Print to PDF", "DriverName": "Microsoft Print To PDF", "PortName": "PORTPROMPT:", "Default": true, "Network": false, "Shared": false, "PrinterStatus": int32(3)},
		},
		DisplayVersion: "24H2",
		OA3Key:         "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
	}
}

func TestBuildWindowsInventoryRawMatchesLegacy(t *testing.T) {
	var want map[string]interface{}
	if err := json.Unmarshal([]byte(legacyRawWS2025), &want); err != nil {
		t.Fatal(err)
	}
	// Intended fix: NULL-serial disks are kept.
	want["disks"] = []interface{}{
		map[string]interface{}{"model": "Disque virtuel Microsoft", "serial": "", "sizeBytes": 214745610240.0, "mediaType": "Fixed hard disk media", "iface": "SCSI"},
		map[string]interface{}{"model": "Disque virtuel Microsoft", "serial": "", "sizeBytes": 268432012800.0, "mediaType": "Fixed hard disk media", "iface": "SCSI"},
	}
	// Keys added since the former script (additive: no legacy key changes).
	want["bios"].(map[string]interface{})["serial"] = "0000-0000-0000-0000-0000-0000-00"
	want["system"] = map[string]interface{}{"manufacturer": "Microsoft Corporation", "model": "Virtual Machine",
		"family": "Virtual Machine", "version": "Hyper-V UEFI Release v4.1", "pcSystemType": 1.0}
	got := normalizeJSONMap(buildWindowsInventoryRaw(snapshotWS2025()))
	if !reflect.DeepEqual(got, want) {
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(want)
		t.Fatalf("raw mismatch\n got: %s\nwant: %s", gb, wb)
	}

	// And the mapped InventoryData equals what the legacy JSON gave (disks aside).
	var legacyRaw map[string]interface{}
	_ = json.Unmarshal([]byte(legacyRawWS2025), &legacyRaw)
	a := &InventoryData{}
	applyWindowsInventoryRaw(a, legacyRaw)
	b := &InventoryData{}
	applyWindowsInventoryRaw(b, got)
	b.Disks = nil
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("InventoryData mismatch\nlegacy: %s\nnative: %s", ja, jb)
	}
}

// A Windows 7 laptop as WMI v6.1 reports it: no ManufacturerIdTxt on Win32_Tpm,
// a 4 GB card whose AdapterRAM (uint32) wraps negative in a VT_I4, a USB
// serial adapter, a battery, half-way roundings, OA3 key absent.
func TestBuildWindowsInventoryRawWin7Laptop(t *testing.T) {
	s := winInvSnapshot{
		CPU:    []wmiRow{{"Name": "  Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz ", "NumberOfCores": int32(2), "NumberOfLogicalProcessors": int32(4), "MaxClockSpeed": int32(2501), "AddressWidth": int32(64)}},
		Memory: []wmiRow{{"DeviceLocator": "DIMM 1", "Capacity": "4294967296", "MemoryType": int32(24), "Speed": int32(1333), "Manufacturer": "Samsung  "}, {"DeviceLocator": "DIMM 2", "Capacity": "1572864", "MemoryType": int32(21)}},
		OS:     []wmiRow{{"Caption": "Microsoft Windows 7 Professionnel ", "Version": "6.1.7601", "TotalVisibleMemorySize": "1536"}},
		Disks:  []wmiRow{{"Model": "ST500LT012 ", "SerialNumber": "  W0V1ABCD", "Size": "500105249280", "MediaType": "Fixed hard disk media", "InterfaceType": "IDE"}},
		GPUs: []wmiRow{
			{"Caption": "NVIDIA Quadro K2000M ", "AdapterRAM": int32(-1), "DriverVersion": "9.18.13.4144", "PNPDeviceID": `pci\VEN_10DE&DEV_0FFB`},
			{"Caption": "Citrix Indirect Display", "PNPDeviceID": `ROOT\DISPLAY\0000`},
		},
		Ports: []wmiRow{
			{"Caption": "Prolific USB-to-Serial Comm Port (com5)", "PNPDeviceID": `USB\VID_067B&PID_2303\5&1`},
			{"Caption": "ECP Printer Port (LPT1)", "PNPDeviceID": `ACPI\PNP0401\4&1`},
		},
		BackupProductKey:   "XXXXX-XXXXX-XXXXX-XXXXX-12345",
		Office:             []officeRegProps{{}, {ClientVersionToReport: "16.0.4266.1001"}},
		OfficeOSPP:         []wmiRow{{"PartialProductKey": "ABCDE", "Name": "Office 16, Office16ProPlusVL_KMS_Client edition"}},
		Battery:            []wmiRow{{"BatteryStatus": int32(2)}},
		BatteryDesigned:    []wmiRow{{"DesignedCapacity": int32(56160)}},
		BatteryFullCharged: []wmiRow{{"FullChargedCapacity": int32(48123)}},
		BatteryCycles:      nil,
		TPM:                []wmiRow{{"PhysicalPresenceVersionInfo": "1.2", "SpecVersion": "1.2, 2, 3", "IsActivated_InitialValue": true, "IsEnabled_InitialValue": true, "IsOwned_InitialValue": false}},
	}
	raw := normalizeJSONMap(buildWindowsInventoryRaw(s))
	inv := &InventoryData{}
	applyWindowsInventoryRaw(inv, raw)

	if inv.CPU.Model != "Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz" || inv.CPU.Cores != 2 || inv.CPU.Threads != 4 || inv.CPU.SpeedMHz != 2501 || inv.CPU.Architecture != "64-bit" {
		t.Errorf("cpu = %+v", inv.CPU)
	}
	// 1536 KB / 1024 = 1.5 -> half to even = 2; 1572864 B = 1.5 MB -> 2.
	if inv.Memory.TotalMB != 2 || len(inv.Memory.Slots) != 2 || inv.Memory.Slots[0].SizeMB != 4096 ||
		inv.Memory.Slots[0].Type != "DDR3" || inv.Memory.Slots[0].Manufacturer != "Samsung" || inv.Memory.Slots[1].SizeMB != 2 || inv.Memory.Slots[1].Type != "DDR2" {
		t.Errorf("memory = %+v", inv.Memory)
	}
	if len(inv.Disks) != 1 || inv.Disks[0].Serial != "W0V1ABCD" || inv.Disks[0].Model != "ST500LT012" || inv.Disks[0].SizeBytes != 500105249280 {
		t.Errorf("disks = %+v", inv.Disks)
	}
	if len(inv.GPU) != 1 || inv.GPU[0].VRAM != "4095 MB" || inv.GPU[0].Model != "NVIDIA Quadro K2000M" {
		t.Errorf("gpu = %+v", inv.GPU)
	}
	if len(inv.ComPorts) != 1 || inv.ComPorts[0].Port != "com5" {
		t.Errorf("comPorts = %+v", inv.ComPorts)
	}
	if inv.OS.Edition != "Microsoft Windows 7 Professionnel" || inv.OS.BuildNumber != "6.1.7601" || inv.OS.DisplayVersion != "" ||
		inv.OS.WindowsKey != "XXXXX-XXXXX-XXXXX-XXXXX-12345" || inv.OS.OfficeVersion != "Office 16.0.4266.1001" || inv.OS.OfficeKey != "ABCDE" {
		t.Errorf("os = %+v", inv.OS)
	}
	// 48123/56160*100 = 85.689... -> 85.7
	if inv.Battery == nil || inv.Battery.HealthPercent != 85.7 || inv.Battery.Status != "AC Power" || inv.Battery.CycleCount != 0 {
		t.Errorf("battery = %+v", inv.Battery)
	}
	if inv.TPM == nil || !inv.TPM.Present || inv.TPM.Status != "Ready" || inv.TPM.ManufacturerName != "" || inv.TPM.Version != "1.2" || inv.TPM.Owned {
		t.Errorf("tpm = %+v", inv.TPM)
	}
	if inv.Printers != nil || inv.Network != nil {
		t.Errorf("printers/network should be empty: %+v %+v", inv.Printers, inv.Network)
	}
}

func TestBuildWindowsInventoryRawOfficeFromOSPPName(t *testing.T) {
	raw := buildWindowsInventoryRaw(winInvSnapshot{
		Office:     []officeRegProps{{ProductReleaseIds: "O365ProPlusRetail", ClientVersionToReport: "16.0.1"}},
		OfficeOSPP: []wmiRow{{"PartialProductKey": "K1234", "Name": "Office 19"}},
	})
	od := raw["osDetails"].(map[string]interface{})
	if od["officeVersion"] != "O365ProPlusRetail" || od["officeKey"] != "K1234" {
		t.Errorf("osDetails = %v", od)
	}
	raw = buildWindowsInventoryRaw(winInvSnapshot{OfficeOSPP: []wmiRow{{"PartialProductKey": "K1234", "Name": "Office 19"}}})
	od = raw["osDetails"].(map[string]interface{})
	if od["officeVersion"] != "Office 19" {
		t.Errorf("osDetails = %v", od)
	}
	// TPM enabled but not activated -> NotReady; nothing -> Disabled.
	raw = buildWindowsInventoryRaw(winInvSnapshot{TPM: []wmiRow{{"IsEnabled_InitialValue": true}}})
	if st := raw["tpm"].(map[string]interface{})["status"]; st != "NotReady" {
		t.Errorf("tpm status = %v", st)
	}
}

func TestBuildWindowsSoftwareList(t *testing.T) {
	got := buildWindowsSoftwareList([]uninstallRecord{
		{DisplayName: "7-Zip 26.00 (x64)", DisplayVersion: "26.00", Publisher: "Igor Pavlov"},
		{DisplayName: "   "},
		{DisplayName: ""},
		{DisplayName: " bun ", InstallLocation: ` C:\Users\x\.bun `},
		{DisplayName: "Adobe Reader", DisplayVersion: "11.0", InstallDate: "20200101"},
		{DisplayName: "ADOBE READER", DisplayVersion: "10.0"}, // duplicate (32-bit view): first one wins
	})
	want := []SoftwareEntry{
		{Name: "7-Zip 26.00 (x64)", Version: "26.00", Publisher: "Igor Pavlov", Source: "registry"},
		{Name: "Adobe Reader", Version: "11.0", InstallDate: "20200101", Source: "registry"},
		{Name: "bun", InstallLocation: `C:\Users\x\.bun`, Source: "registry"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestWMIRowConversions(t *testing.T) {
	r := wmiRow{"neg": int32(-2147483648), "s64": "18446744073709551615", "b": true, "f": float32(1.5), "arr": []interface{}{"a", "", nil, "b"}, "u8": uint8(7)}
	if r.uint32v("neg") != 2147483648 {
		t.Errorf("uint32v = %d", r.uint32v("neg"))
	}
	if r.int64v("u8") != 7 || r.int64v("missing") != 0 || r.str("missing") != "" || r.str("b") != "True" {
		t.Errorf("conversions")
	}
	if r.int64v("s64") != -1 { // uint64 max reinterpreted, never a panic
		t.Errorf("s64 = %d", r.int64v("s64"))
	}
	if got := r.strs("arr"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("strs = %v", got)
	}
	if r.float64v("f") != 1.5 || !r.boolv("b") || r.boolv("missing") {
		t.Errorf("float/bool")
	}
	if psRound(2.5, 0) != 2 || psRound(3.5, 0) != 4 || psRound(85.68, 1) != 85.7 {
		t.Errorf("psRound")
	}
}

// raw["system"] / raw["bios"]["serial"] as Oblireach Desktop reads them
// (raw.wmi.system.{manufacturer, model, family|version, pcSystemType},
// raw.wmi.bios.serial), from WMI rows of real machine kinds.
func TestBuildWindowsInventoryRawMachineIdentity(t *testing.T) {
	cases := []struct {
		name       string
		bios       wmiRow
		cs, csp    wmiRow
		wantSerial string
		wantSystem map[string]interface{}
	}{
		{
			name:       "Dell Latitude (Service Tag)",
			bios:       wmiRow{"Manufacturer": "Dell Inc.", "SMBIOSBIOSVersion": "1.31.0", "SerialNumber": "ABC1234"},
			cs:         wmiRow{"Manufacturer": "Dell Inc.", "Model": "Latitude 5420", "SystemFamily": "Latitude", "PCSystemType": int32(2)},
			csp:        wmiRow{"Version": ""},
			wantSerial: "ABC1234",
			wantSystem: map[string]interface{}{"manufacturer": "Dell Inc.", "model": "Latitude 5420", "family": "Latitude", "version": "", "pcSystemType": 2.0},
		},
		{
			name:       "Lenovo ThinkPad (machine type in Model, name in Version)",
			bios:       wmiRow{"Manufacturer": "LENOVO", "SerialNumber": " PF3ABCDE "},
			cs:         wmiRow{"Manufacturer": "LENOVO", "Model": "21AH00BXFR", "SystemFamily": "ThinkPad T14 Gen 3", "PCSystemType": int32(2)},
			csp:        wmiRow{"Version": "ThinkPad T14 Gen 3"},
			wantSerial: "PF3ABCDE",
			wantSystem: map[string]interface{}{"manufacturer": "LENOVO", "model": "21AH00BXFR", "family": "ThinkPad T14 Gen 3", "version": "ThinkPad T14 Gen 3", "pcSystemType": 2.0},
		},
		{
			name:       "Hyper-V VM",
			bios:       wmiRow{"Manufacturer": "Microsoft Corporation", "SerialNumber": "0000-0000-0000-0000-0000-0000-00"},
			cs:         wmiRow{"Manufacturer": "Microsoft Corporation", "Model": "Virtual Machine", "SystemFamily": "Virtual Machine", "PCSystemType": int32(1)},
			csp:        wmiRow{"Version": "Hyper-V UEFI Release v4.1"},
			wantSerial: "0000-0000-0000-0000-0000-0000-00",
			wantSystem: map[string]interface{}{"manufacturer": "Microsoft Corporation", "model": "Virtual Machine", "family": "Virtual Machine", "version": "Hyper-V UEFI Release v4.1", "pcSystemType": 1.0},
		},
		{
			// Windows 7: no SystemFamily (SELECT * leaves it absent); NULL
			// serial (white box) -> "".
			name:       "Windows 7 white box",
			bios:       wmiRow{"Manufacturer": "American Megatrends Inc."},
			cs:         wmiRow{"Manufacturer": "To Be Filled By O.E.M.", "Model": "To Be Filled By O.E.M.", "PCSystemType": int32(1)},
			wantSerial: "",
			wantSystem: map[string]interface{}{"manufacturer": "To Be Filled By O.E.M.", "model": "To Be Filled By O.E.M.", "family": "", "version": "", "pcSystemType": 1.0},
		},
		{
			// Win32_ComputerSystem query failed: keys present, empty, no pcSystemType.
			name:       "no Win32_ComputerSystem",
			wantSystem: map[string]interface{}{"manufacturer": "", "model": "", "family": "", "version": ""},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap := winInvSnapshot{}
			if c.bios != nil {
				snap.BIOS = []wmiRow{c.bios}
			}
			if c.cs != nil {
				snap.System = []wmiRow{c.cs}
			}
			if c.csp != nil {
				snap.Product = []wmiRow{c.csp}
			}
			raw := normalizeJSONMap(buildWindowsInventoryRaw(snap))
			if got := raw["bios"].(map[string]interface{})["serial"]; got != c.wantSerial {
				t.Errorf("bios.serial = %q, want %q", got, c.wantSerial)
			}
			if got := raw["system"]; !reflect.DeepEqual(got, c.wantSystem) {
				t.Errorf("system = %#v, want %#v", got, c.wantSystem)
			}
			// The legacy-shaped mapping is untouched by the added keys.
			inv := &InventoryData{}
			applyWindowsInventoryRaw(inv, raw)
			if b, _ := json.Marshal(inv.BIOS); strings.Contains(string(b), "serial") {
				t.Errorf("InventoryData.BIOS changed: %s", b)
			}
		})
	}
}
