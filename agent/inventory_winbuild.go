package main

// Windows hardware inventory and installed-software list, built from native
// WMI rows / registry records (inventory_windows.go collects them). These
// builders are platform-independent so they are unit-tested everywhere with
// recorded rows.
//
// Contract: buildWindowsInventoryRaw returns EXACTLY the map the former
// single PowerShell script printed with `$result | ConvertTo-Json` (same keys,
// same value conventions: [math]::Round half-to-even, the same enum-to-name
// switches, the same filters), so applyWindowsInventoryRaw — unchanged —
// produces the same InventoryData and inv.Raw["wmi"] keeps its shape. Only
// differences, on purpose: a NULL WMI string no longer drops its item (the old
// script's `$null.Trim()` threw inside the hashtable and silently lost e.g.
// every disk without SerialNumber, such as Hyper-V virtual disks); and keys
// ADDED since (never changed nor removed): bios.serial and system.* (see
// windowsSystemRaw), read by Oblireach Desktop.

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

// winInvSnapshot: everything the inventory reads, as collected natively.
type winInvSnapshot struct {
	CPU      []wmiRow // Win32_Processor
	Memory   []wmiRow // Win32_PhysicalMemory
	OS       []wmiRow // Win32_OperatingSystem
	Disks    []wmiRow // Win32_DiskDrive
	NICs     []wmiRow // Win32_NetworkAdapterConfiguration WHERE IPEnabled
	GPUs     []wmiRow // Win32_VideoController
	Board    []wmiRow // Win32_BaseBoard
	BIOS     []wmiRow // Win32_BIOS
	System   []wmiRow // Win32_ComputerSystem (added: not in the former script)
	Product  []wmiRow // Win32_ComputerSystemProduct (added: not in the former script)
	Printers []wmiRow // Win32_Printer
	Ports    []wmiRow // Win32_PnPEntity of the Ports class

	DisplayVersion   string           // HKLM\...\Windows NT\CurrentVersion DisplayVersion
	OA3Key           string           // SoftwareLicensingService.OA3xOriginalProductKey
	BackupProductKey string           // ...\SoftwareProtectionPlatform BackupProductKeyDefault
	Office           []officeRegProps // existing Office registry keys, in probe order
	OfficeOSPP       []wmiRow         // SoftwareLicensingProduct (Office app id, with key)

	Battery            []wmiRow // Win32_Battery
	BatteryDesigned    []wmiRow // root\WMI BatteryStaticData
	BatteryFullCharged []wmiRow // root\WMI BatteryFullChargedCapacity
	BatteryCycles      []wmiRow // root\WMI BatteryCycleCount

	TPM []wmiRow // root\cimv2\Security\MicrosoftTpm Win32_Tpm
}

// officeRegProps: the two values the script read from an Office key.
type officeRegProps struct {
	ProductReleaseIds     string
	ClientVersionToReport string
}

// officeRegistryPaths: probed in this order (HKLM), as the script did.
var officeRegistryPaths = []string{
	`SOFTWARE\Microsoft\Office\ClickToRun\Configuration`,
	`SOFTWARE\Microsoft\Office\16.0\Common\InstalledPackages`,
}

// psRound mirrors [math]::Round(x, digits): .NET rounds half to even.
func psRound(x float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.RoundToEven(x*p) / p
}

func firstRow(rows []wmiRow) wmiRow {
	if len(rows) == 0 {
		return wmiRow{}
	}
	return rows[0]
}

func memoryTypeName(t int64) string {
	switch t {
	case 20:
		return "DDR"
	case 21:
		return "DDR2"
	case 24:
		return "DDR3"
	case 26:
		return "DDR4"
	case 34:
		return "DDR5"
	}
	return "Unknown"
}

func printerStatusName(s int64) string {
	switch s {
	case 1:
		return "Other"
	case 2:
		return "Unknown"
	case 3:
		return "Idle"
	case 4:
		return "Printing"
	case 5:
		return "Warmup"
	case 6:
		return "Stopped Printing"
	case 7:
		return "Offline"
	}
	return "Unknown"
}

func batteryStatusName(s int64) string {
	switch s {
	case 1:
		return "Discharging"
	case 2:
		return "AC Power"
	case 3:
		return "Full"
	case 4:
		return "Low"
	case 5:
		return "Critical"
	case 6:
		return "Charging"
	}
	return "Unknown"
}

// PowerShell -match is case-insensitive.
var (
	reComPort   = regexp.MustCompile(`(?i)\((COM\d+)\)`)
	rePCIDevice = regexp.MustCompile(`(?i)^PCI`)
)

// buildWindowsInventoryRaw: see the file comment.
func buildWindowsInventoryRaw(s winInvSnapshot) map[string]interface{} {
	cpu := firstRow(s.CPU)
	osr := firstRow(s.OS)
	mb := firstRow(s.Board)
	bios := firstRow(s.BIOS)

	memSlots := []interface{}{}
	for _, m := range s.Memory {
		memSlots = append(memSlots, map[string]interface{}{
			"slot":         m.str("DeviceLocator"),
			"sizeMb":       psRound(float64(m.int64v("Capacity"))/1048576, 0),
			"type":         memoryTypeName(m.int64v("MemoryType")),
			"speedMhz":     m.uint32v("Speed"),
			"manufacturer": strings.TrimSpace(m.str("Manufacturer")),
		})
	}

	disks := []interface{}{}
	for _, d := range s.Disks {
		disks = append(disks, map[string]interface{}{
			"model":     strings.TrimSpace(d.str("Model")),
			"serial":    strings.TrimSpace(d.str("SerialNumber")),
			"sizeBytes": d.int64v("Size"),
			"mediaType": d.str("MediaType"),
			"iface":     d.str("InterfaceType"),
		})
	}

	nics := []interface{}{}
	for _, n := range s.NICs {
		addrs := []interface{}{}
		for _, a := range n.strs("IPAddress") {
			addrs = append(addrs, a)
		}
		nics = append(nics, map[string]interface{}{
			"name":  strings.TrimSpace(n.str("Description")),
			"mac":   n.str("MACAddress"),
			"addrs": addrs,
		})
	}

	gpus := []interface{}{}
	for _, g := range s.GPUs {
		if !rePCIDevice.MatchString(g.str("PNPDeviceID")) {
			continue
		}
		gpus = append(gpus, map[string]interface{}{
			"model":     strings.TrimSpace(g.str("Caption")),
			"vramBytes": g.uint32v("AdapterRAM"),
			"driverVer": g.str("DriverVersion"),
		})
	}

	printers := []interface{}{}
	for _, p := range s.Printers {
		printers = append(printers, map[string]interface{}{
			"name":      p.str("Name"),
			"driver":    p.str("DriverName"),
			"port":      p.str("PortName"),
			"isDefault": p.boolv("Default"),
			"isNetwork": p.boolv("Network"),
			"isShared":  p.boolv("Shared"),
			"status":    printerStatusName(p.int64v("PrinterStatus")),
		})
	}

	comPorts := []interface{}{}
	for _, p := range s.Ports {
		caption := p.str("Caption")
		m := reComPort.FindStringSubmatch(caption)
		if m == nil {
			continue
		}
		comPorts = append(comPorts, map[string]interface{}{
			"port":        m[1],
			"description": caption,
			"deviceId":    p.str("PNPDeviceID"),
		})
	}

	raw := map[string]interface{}{
		"cpu": map[string]interface{}{
			"model":   strings.TrimSpace(cpu.str("Name")),
			"cores":   cpu.int64v("NumberOfCores"),
			"threads": cpu.int64v("NumberOfLogicalProcessors"),
			"speed":   cpu.uint32v("MaxClockSpeed"),
			"arch":    cpu.int64v("AddressWidth"),
		},
		"memTotalMB": psRound(float64(osr.int64v("TotalVisibleMemorySize"))/1024, 0),
		"memSlots":   memSlots,
		"disks":      disks,
		"nics":       nics,
		"gpus":       gpus,
		"mb": map[string]interface{}{
			"manufacturer": strings.TrimSpace(mb.str("Manufacturer")),
			"product":      strings.TrimSpace(mb.str("Product")),
			"version":      strings.TrimSpace(mb.str("Version")),
			"serial":       strings.TrimSpace(mb.str("SerialNumber")),
		},
		"bios": map[string]interface{}{
			"vendor":  strings.TrimSpace(bios.str("Manufacturer")),
			"version": strings.TrimSpace(bios.str("SMBIOSBIOSVersion")),
			"date":    bios.str("ReleaseDate"),
			// Added (not in the former script): the maker's serial number,
			// what `Get-CimInstance Win32_BIOS | Select SerialNumber` shows
			// (Dell: the Service Tag).
			"serial": strings.TrimSpace(bios.str("SerialNumber")),
		},
		"system":   windowsSystemRaw(firstRow(s.System), firstRow(s.Product)),
		"printers": printers,
		"comPorts": comPorts,
	}

	// OS details.
	winKey := s.OA3Key
	if winKey == "" {
		winKey = s.BackupProductKey
	}
	officeVer := ""
	for _, o := range s.Office {
		if o.ProductReleaseIds != "" {
			officeVer = o.ProductReleaseIds
			break
		}
		if o.ClientVersionToReport != "" {
			officeVer = "Office " + o.ClientVersionToReport
			break
		}
	}
	officeKey := ""
	if len(s.OfficeOSPP) > 0 {
		ospp := s.OfficeOSPP[0]
		officeKey = ospp.str("PartialProductKey")
		if officeVer == "" && ospp.str("Name") != "" {
			officeVer = ospp.str("Name")
		}
	}
	raw["osDetails"] = map[string]interface{}{
		"edition":        strings.TrimSpace(osr.str("Caption")),
		"displayVersion": s.DisplayVersion,
		"buildNumber":    osr.str("Version"),
		"windowsKey":     winKey,
		"officeVersion":  officeVer,
		"officeKey":      officeKey,
	}

	// Battery.
	if len(s.Battery) > 0 {
		bat := s.Battery[0]
		design := firstRow(s.BatteryDesigned).int64v("DesignedCapacity")
		full := firstRow(s.BatteryFullCharged).int64v("FullChargedCapacity")
		cycle := firstRow(s.BatteryCycles).int64v("CycleCount")
		health := 0.0
		if design > 0 {
			health = psRound(float64(full)/float64(design)*100, 1)
		}
		raw["battery"] = map[string]interface{}{
			"present":        true,
			"designCapacity": design,
			"fullCapacity":   full,
			"healthPercent":  health,
			"cycleCount":     cycle,
			"status":         batteryStatusName(bat.int64v("BatteryStatus")),
		}
	}

	// TPM.
	if len(s.TPM) > 0 {
		t := s.TPM[0]
		activated := t.boolv("IsActivated_InitialValue")
		enabled := t.boolv("IsEnabled_InitialValue")
		status := "Disabled"
		if activated && enabled {
			status = "Ready"
		} else if enabled {
			status = "NotReady"
		}
		raw["tpm"] = map[string]interface{}{
			"present":          true,
			"manufacturerName": t.str("ManufacturerIdTxt"),
			"version":          t.str("PhysicalPresenceVersionInfo"),
			"specVersion":      t.str("SpecVersion"),
			"status":           status,
			"activated":        activated,
			"enabled":          enabled,
			"owned":            t.boolv("IsOwned_InitialValue"),
		}
	} else {
		raw["tpm"] = map[string]interface{}{"present": false}
	}
	return raw
}

// windowsSystemRaw: raw["system"], added after the former script (which had
// no such key) — the machine as its maker names it, read by Oblireach
// Desktop's Info panel (raw.wmi.system.{manufacturer, model, family|version,
// pcSystemType}). cs = Win32_ComputerSystem, csp = Win32_ComputerSystemProduct.
// pcSystemType (1 desktop, 2 mobile, 4/5/7 server, 8 slate...) is left out
// when WMI has none (Windows < Vista).
func windowsSystemRaw(cs, csp wmiRow) map[string]interface{} {
	m := map[string]interface{}{
		"manufacturer": strings.TrimSpace(cs.str("Manufacturer")),
		"model":        strings.TrimSpace(cs.str("Model")),
		"family":       strings.TrimSpace(cs.str("SystemFamily")),
		"version":      strings.TrimSpace(csp.str("Version")),
	}
	if cs.has("PCSystemType") {
		m["pcSystemType"] = cs.int64v("PCSystemType")
	}
	return m
}

// normalizeJSONMap round-trips a map through JSON so its values have the
// types json.Unmarshal produces (float64, []interface{}...), i.e. exactly
// what the former `ConvertTo-Json` output decoded to.
func normalizeJSONMap(m map[string]interface{}) map[string]interface{} {
	b, err := json.Marshal(m)
	if err != nil {
		return m
	}
	var out map[string]interface{}
	if json.Unmarshal(b, &out) != nil {
		return m
	}
	return out
}

// ── Installed software (registry Uninstall keys) ──────────────────────────────

// uninstallRecord: the values read from one Uninstall subkey (registry
// values already converted to text as Get-ItemProperty showed them).
type uninstallRecord struct {
	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string
	InstallLocation string
}

// buildWindowsSoftwareList reproduces the former script: entries with a
// non-blank DisplayName, `Sort-Object DisplayName -Unique` (case-insensitive,
// one entry per name — the first one met in probe order HKLM 64-bit, HKLM
// WOW6432Node, HKCU), fields trimmed, Source "registry".
func buildWindowsSoftwareList(records []uninstallRecord) []SoftwareEntry {
	seen := map[string]bool{}
	var entries []SoftwareEntry
	for _, r := range records {
		name := strings.TrimSpace(r.DisplayName)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, SoftwareEntry{
			Name:            name,
			Version:         strings.TrimSpace(r.DisplayVersion),
			Publisher:       strings.TrimSpace(r.Publisher),
			InstallDate:     strings.TrimSpace(r.InstallDate),
			InstallLocation: strings.TrimSpace(r.InstallLocation),
			Source:          "registry",
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries
}
