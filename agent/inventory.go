package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ── Inventory data types ───────────────────────────────────────────────────────

type CpuInfo struct {
	Model       string  `json:"model"`
	Cores       int     `json:"cores"`
	Threads     int     `json:"threads"`
	SpeedMHz    float64 `json:"speedMhz,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

type MemorySlot struct {
	Slot         string `json:"slot,omitempty"`
	SizeMB       uint64 `json:"sizeMb"`
	Type         string `json:"type,omitempty"`
	SpeedMHz     int    `json:"speedMhz,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
}

type MemoryInfo struct {
	TotalMB uint64       `json:"totalMb"`
	Slots   []MemorySlot `json:"slots,omitempty"`
}

type DiskInfo struct {
	Model      string   `json:"model,omitempty"`
	Serial     string   `json:"serial,omitempty"`
	Type       string   `json:"type,omitempty"` // SSD, HDD, NVMe, Unknown
	SizeBytes  int64    `json:"sizeBytes"`
	Partitions []string `json:"partitions,omitempty"`
	Interface  string   `json:"interface,omitempty"` // SATA, NVMe, USB, etc.
}

type NetworkInfo struct {
	Name        string   `json:"name"`
	MACAddress  string   `json:"macAddress,omitempty"`
	Type        string   `json:"type,omitempty"` // Ethernet, WiFi, Virtual
	Addresses   []string `json:"addresses,omitempty"`
	Speed       string   `json:"speed,omitempty"`
}

type GpuInfo struct {
	Model     string `json:"model"`
	VRAM      string `json:"vram,omitempty"`
	DriverVer string `json:"driverVersion,omitempty"`
}

type MotherboardInfo struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Version      string `json:"version,omitempty"`
	Serial       string `json:"serial,omitempty"`
}

type TpmInfo struct {
	Present          bool   `json:"present"`
	ManufacturerName string `json:"manufacturerName,omitempty"`
	Version          string `json:"version,omitempty"`     // "2.0", "1.2"
	SpecVersion      string `json:"specVersion,omitempty"` // "2.0, 0, 1.59"
	Status           string `json:"status,omitempty"`      // Ready, NotReady, Disabled
	Activated        bool   `json:"activated"`
	Enabled          bool   `json:"enabled"`
	Owned            bool   `json:"owned"`
}

type BiosInfo struct {
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
	Date    string `json:"date,omitempty"`
}

type BitLockerVolume struct {
	DriveLetter          string   `json:"driveLetter"`
	Status               string   `json:"status"`               // FullyEncrypted, FullyDecrypted, EncryptionInProgress, DecryptionInProgress, etc.
	ProtectionStatus     string   `json:"protectionStatus"`     // On, Off, Unknown
	EncryptionPercentage int      `json:"encryptionPercentage"` // 0-100
	RecoveryKeys         []string `json:"recoveryKeys"`
}

type SoftwareEntry struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	InstallDate     string `json:"installDate,omitempty"`
	InstallLocation string `json:"installLocation,omitempty"`
	Source          string `json:"source,omitempty"`
	PackageID       string `json:"packageId,omitempty"`
}

type OSDetails struct {
	Edition        string `json:"edition,omitempty"`        // "Windows 11 Pro", "macOS Tahoe", "Debian 12"
	DisplayVersion string `json:"displayVersion,omitempty"` // "25H2", "26.3.1", "12.8"
	BuildNumber    string `json:"buildNumber,omitempty"`    // "26200.8037", "25D2128"
	WindowsKey     string `json:"windowsKey,omitempty"`     // Product key (partial)
	OfficeVersion  string `json:"officeVersion,omitempty"`  // "Microsoft 365 Apps" / "Office 2021"
	OfficeKey      string `json:"officeKey,omitempty"`      // Last 5 chars of product key
}

type PrinterInfo struct {
	Name      string `json:"name"`
	Driver    string `json:"driver,omitempty"`
	Port      string `json:"port,omitempty"`
	IsDefault bool   `json:"isDefault"`
	IsNetwork bool   `json:"isNetwork"`
	IsShared  bool   `json:"isShared"`
	Status    string `json:"status,omitempty"`
}

type ComPortInfo struct {
	Port        string `json:"port"`
	Description string `json:"description,omitempty"`
	DeviceID    string `json:"deviceId,omitempty"`
}

type BatteryInfo struct {
	Present         bool    `json:"present"`
	DesignCapacity  int     `json:"designCapacity,omitempty"`  // mWh
	FullCapacity    int     `json:"fullCapacity,omitempty"`    // mWh
	CurrentCapacity int     `json:"currentCapacity,omitempty"` // mWh
	HealthPercent   float64 `json:"healthPercent,omitempty"`   // fullCapacity/designCapacity * 100
	CycleCount      int     `json:"cycleCount,omitempty"`
	Status          string  `json:"status,omitempty"` // Charging, Discharging, Full, etc.
}

type InventoryData struct {
	CPU         CpuInfo                `json:"cpu"`
	Memory      MemoryInfo             `json:"memory"`
	Disks       []DiskInfo             `json:"disks"`
	Network     []NetworkInfo          `json:"networkInterfaces"`
	GPU         []GpuInfo              `json:"gpu"`
	Motherboard MotherboardInfo        `json:"motherboard"`
	BIOS        BiosInfo               `json:"bios"`
	TPM         *TpmInfo               `json:"tpm,omitempty"`
	OS          OSDetails              `json:"os"`
	Battery     *BatteryInfo           `json:"battery,omitempty"`
	Software    []SoftwareEntry        `json:"software,omitempty"`
	BitLocker   []BitLockerVolume      `json:"bitlocker,omitempty"`
	Printers    []PrinterInfo          `json:"printers,omitempty"`
	ComPorts    []ComPortInfo          `json:"comPorts,omitempty"`
	Raw         map[string]interface{} `json:"raw,omitempty"`
	ScannedAt   time.Time              `json:"scannedAt"`
}

// ── Entry point ───────────────────────────────────────────────────────────────

// ScanInventory collects hardware and software inventory for the current platform.
func ScanInventory() (*InventoryData, error) {
	inv := &InventoryData{
		ScannedAt: time.Now().UTC(),
		Raw:       make(map[string]interface{}),
	}

	var err error
	switch runtime.GOOS {
	case "windows":
		err = scanWindowsInventory(inv)
	case "linux":
		err = scanLinuxInventory(inv)
	case "darwin":
		err = scanDarwinInventory(inv)
	case "freebsd":
		err = scanFreeBSDInventory(inv)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	if err != nil {
		// Non-fatal: return what was collected alongside the error.
		log.Printf("Inventory scan partial error: %v", err)
	}

	// Scan installed software (platform-aware).
	inv.Software = scanInstalledSoftware()

	// BitLocker recovery keys (Windows only).
	if runtime.GOOS == "windows" {
		inv.BitLocker = scanBitLocker()
	}

	return inv, nil
}

// PostInventory POSTs the collected inventory to the server.
func PostInventory(inv *InventoryData, cfg *Config) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.ServerURL+"/api/agent/inventory", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build inventory request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cfg.APIKey)
	req.Header.Set("X-Device-UUID", currentDeviceUUID())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post inventory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("inventory POST returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Windows ───────────────────────────────────────────────────────────────────

// scanWindowsInventory collects the hardware inventory natively (WMI through
// COM + registry, inventory_windows.go) — no PowerShell, so it works the same
// on PowerShell 2.0 (Windows 7 / 2008 R2, no ConvertTo-Json) and on systems
// without wmic. buildWindowsInventoryRaw yields the very map the former
// PowerShell script printed as JSON; applyWindowsInventoryRaw maps it.
func scanWindowsInventory(inv *InventoryData) error {
	snap, err := collectWindowsInventorySnapshot()
	if err != nil {
		return fmt.Errorf("wmi inventory: %w", err)
	}
	raw := normalizeJSONMap(buildWindowsInventoryRaw(snap))
	inv.Raw["wmi"] = raw
	applyWindowsInventoryRaw(inv, raw)
	return nil
}

// applyWindowsInventoryRaw maps the inventory map (keys of the former
// PowerShell JSON) onto InventoryData.
func applyWindowsInventoryRaw(inv *InventoryData, raw map[string]interface{}) {

	// CPU
	if cpuRaw, ok := raw["cpu"].(map[string]interface{}); ok {
		inv.CPU = CpuInfo{
			Model:        stringField(cpuRaw, "model"),
			Cores:        intField(cpuRaw, "cores"),
			Threads:      intField(cpuRaw, "threads"),
			SpeedMHz:     float64(intField(cpuRaw, "speed")),
			Architecture: fmt.Sprintf("%d-bit", intField(cpuRaw, "arch")),
		}
	}

	// Memory
	inv.Memory.TotalMB = uint64(int64Field(raw, "memTotalMB"))
	if slots, ok := raw["memSlots"].([]interface{}); ok {
		for _, s := range slots {
			if m, ok := s.(map[string]interface{}); ok {
				inv.Memory.Slots = append(inv.Memory.Slots, MemorySlot{
					Slot:         stringField(m, "slot"),
					SizeMB:       uint64(int64Field(m, "sizeMb")),
					Type:         stringField(m, "type"),
					SpeedMHz:     intField(m, "speedMhz"),
					Manufacturer: stringField(m, "manufacturer"),
				})
			}
		}
	}

	// Disks
	if diskArr, ok := raw["disks"].([]interface{}); ok {
		for _, d := range diskArr {
			if dm, ok := d.(map[string]interface{}); ok {
				mediaType := strings.ToLower(stringField(dm, "mediaType"))
				iface := stringField(dm, "iface")
				dtype := classifyDisk(mediaType, iface, stringField(dm, "model"))
				inv.Disks = append(inv.Disks, DiskInfo{
					Model:     stringField(dm, "model"),
					Serial:    strings.TrimSpace(stringField(dm, "serial")),
					Type:      dtype,
					SizeBytes: int64Field(dm, "sizeBytes"),
					Interface: iface,
				})
			}
		}
	}

	// Network
	if nicArr, ok := raw["nics"].([]interface{}); ok {
		for _, n := range nicArr {
			if nm, ok := n.(map[string]interface{}); ok {
				var addrs []string
				if a, ok := nm["addrs"].([]interface{}); ok {
					for _, addr := range a {
						if s, ok := addr.(string); ok && s != "" {
							addrs = append(addrs, s)
						}
					}
				}
				inv.Network = append(inv.Network, NetworkInfo{
					Name:       stringField(nm, "name"),
					MACAddress: stringField(nm, "mac"),
					Addresses:  addrs,
				})
			}
		}
	}

	// GPU
	if gpuArr, ok := raw["gpus"].([]interface{}); ok {
		for _, g := range gpuArr {
			if gm, ok := g.(map[string]interface{}); ok {
				vramBytes := int64Field(gm, "vramBytes")
				vram := ""
				if vramBytes > 0 {
					vram = fmt.Sprintf("%d MB", vramBytes/1048576)
				}
				inv.GPU = append(inv.GPU, GpuInfo{
					Model:     stringField(gm, "model"),
					VRAM:      vram,
					DriverVer: stringField(gm, "driverVer"),
				})
			}
		}
	}

	// Motherboard
	if mb, ok := raw["mb"].(map[string]interface{}); ok {
		inv.Motherboard = MotherboardInfo{
			Manufacturer: stringField(mb, "manufacturer"),
			Product:      stringField(mb, "product"),
			Version:      stringField(mb, "version"),
			Serial:       stringField(mb, "serial"),
		}
	}

	// BIOS
	if bios, ok := raw["bios"].(map[string]interface{}); ok {
		inv.BIOS = BiosInfo{
			Vendor:  stringField(bios, "vendor"),
			Version: stringField(bios, "version"),
			Date:    stringField(bios, "date"),
		}
	}

	// Printers
	if printerArr, ok := raw["printers"].([]interface{}); ok {
		for _, p := range printerArr {
			if pm, ok := p.(map[string]interface{}); ok {
				isDefault, _ := pm["isDefault"].(bool)
				isNetwork, _ := pm["isNetwork"].(bool)
				isShared, _ := pm["isShared"].(bool)
				inv.Printers = append(inv.Printers, PrinterInfo{
					Name:      stringField(pm, "name"),
					Driver:    stringField(pm, "driver"),
					Port:      stringField(pm, "port"),
					IsDefault: isDefault,
					IsNetwork: isNetwork,
					IsShared:  isShared,
					Status:    stringField(pm, "status"),
				})
			}
		}
	}

	// COM ports
	if portArr, ok := raw["comPorts"].([]interface{}); ok {
		for _, p := range portArr {
			if pm, ok := p.(map[string]interface{}); ok {
				inv.ComPorts = append(inv.ComPorts, ComPortInfo{
					Port:        stringField(pm, "port"),
					Description: stringField(pm, "description"),
					DeviceID:    stringField(pm, "deviceId"),
				})
			}
		}
	}

	// TPM
	if tpm, ok := raw["tpm"].(map[string]interface{}); ok {
		present := false
		if v, ok := tpm["present"].(bool); ok {
			present = v
		}
		info := &TpmInfo{Present: present}
		if present {
			info.ManufacturerName = stringField(tpm, "manufacturerName")
			info.Version = stringField(tpm, "version")
			info.SpecVersion = stringField(tpm, "specVersion")
			info.Status = stringField(tpm, "status")
			if v, ok := tpm["activated"].(bool); ok {
				info.Activated = v
			}
			if v, ok := tpm["enabled"].(bool); ok {
				info.Enabled = v
			}
			if v, ok := tpm["owned"].(bool); ok {
				info.Owned = v
			}
		}
		inv.TPM = info
	}

	// OS Details
	if od, ok := raw["osDetails"].(map[string]interface{}); ok {
		inv.OS = OSDetails{
			Edition:        stringField(od, "edition"),
			DisplayVersion: stringField(od, "displayVersion"),
			BuildNumber:    stringField(od, "buildNumber"),
			WindowsKey:     stringField(od, "windowsKey"),
			OfficeVersion:  stringField(od, "officeVersion"),
			OfficeKey:      stringField(od, "officeKey"),
		}
	}

	// Battery
	if bat, ok := raw["battery"].(map[string]interface{}); ok {
		inv.Battery = &BatteryInfo{
			Present:        true,
			DesignCapacity:  intField(bat, "designCapacity"),
			FullCapacity:    intField(bat, "fullCapacity"),
			HealthPercent:   float64Field(bat, "healthPercent"),
			CycleCount:      intField(bat, "cycleCount"),
			Status:          stringField(bat, "status"),
		}
	}
}

// ── Linux ─────────────────────────────────────────────────────────────────────

func scanLinuxInventory(inv *InventoryData) error {
	// CPU from /proc/cpuinfo
	if out, err := newCmd("cat", "/proc/cpuinfo").Output(); err == nil {
		inv.CPU = parseLinuxCPUInfo(string(out))
	}

	// Memory from /proc/meminfo
	if out, err := newCmd("cat", "/proc/meminfo").Output(); err == nil {
		inv.Memory = parseLinuxMemInfo(string(out))
	}

	// Disks via lsblk JSON
	if out, err := newCmd("lsblk", "-J", "-o", "NAME,MODEL,SERIAL,TYPE,SIZE,TRAN,MOUNTPOINT").Output(); err == nil {
		inv.Disks = parseLinuxLsblk(out)
	}

	// Network interfaces via ip command
	if out, err := newCmd("ip", "-j", "addr").Output(); err == nil {
		inv.Network = parseLinuxIPAddr(out)
	}

	// GPU via lspci
	if out, err := newCmd("lspci").Output(); err == nil {
		inv.GPU = parseLinuxGPU(string(out))
	}

	// Motherboard from DMI
	inv.Motherboard = readLinuxDMI()

	// The machine itself (maker, model, serial, chassis) as raw.dmi, read by
	// Oblireach Desktop's Info panel. product_serial is root-only (the agent
	// runs as root).
	if dmi := readLinuxDMIRaw(linuxDMIDir); len(dmi) > 0 {
		inv.Raw["dmi"] = dmi
	}

	// BIOS from DMI
	inv.BIOS = readLinuxBIOS()

	// OS Details
	inv.OS = collectLinuxOSDetails()

	// Battery
	inv.Battery = collectLinuxBattery()

	// Printers (CUPS)
	inv.Printers = scanCupsPrinters()

	// COM/serial ports
	inv.ComPorts = scanLinuxComPorts()

	return nil
}

// scanLinuxComPorts lists real serial devices under /dev. ttyUSB*/ttyACM*
// nodes only exist when a device is actually plugged in, so they're always
// real. ttyS* nodes are pre-created for every possible legacy UART regardless
// of whether hardware backs them — we only keep the ones with a "device"
// symlink under /sys/class/tty, which indicates real hardware.
func scanLinuxComPorts() []ComPortInfo {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return nil
	}
	var ports []ComPortInfo
	for _, e := range entries {
		name := e.Name()
		isUSBSerial := strings.HasPrefix(name, "ttyUSB") || strings.HasPrefix(name, "ttyACM")
		isLegacySerial := strings.HasPrefix(name, "ttyS")
		if !isUSBSerial && !isLegacySerial {
			continue
		}
		if isLegacySerial {
			if _, err := os.Stat("/sys/class/tty/" + name + "/device"); err != nil {
				continue // phantom port, no hardware behind it
			}
		}
		devPath := "/dev/" + name
		desc := ""
		if out, err := newCmd("udevadm", "info", "-q", "property", "-n", devPath).Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(l, "ID_MODEL=") {
					desc = strings.ReplaceAll(strings.TrimPrefix(l, "ID_MODEL="), "_", " ")
					break
				}
			}
		}
		ports = append(ports, ComPortInfo{Port: devPath, Description: desc})
	}
	return ports
}

// scanCupsPrinters lists printers via `lpstat` (CUPS) — shared by Linux and
// macOS, both of which use CUPS as their printing subsystem.
func scanCupsPrinters() []PrinterInfo {
	out, err := newCmd("lpstat", "-p").Output()
	if err != nil {
		return nil
	}
	defaultName := ""
	if dout, err := newCmd("lpstat", "-d").Output(); err == nil {
		if idx := strings.Index(string(dout), ": "); idx >= 0 {
			defaultName = strings.TrimSpace(string(dout)[idx+2:])
		}
	}
	var printers []PrinterInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "printer ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		status := "Unknown"
		switch {
		case strings.Contains(line, "is idle"):
			status = "Idle"
		case strings.Contains(line, "printing"):
			status = "Printing"
		case strings.Contains(line, "disabled"):
			status = "Offline"
		}
		printers = append(printers, PrinterInfo{
			Name:      name,
			IsDefault: name != "" && name == defaultName,
			Status:    status,
		})
	}
	return printers
}

func parseLinuxCPUInfo(data string) CpuInfo {
	info := CpuInfo{Architecture: runtime.GOARCH}
	coreSet := make(map[string]bool)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "model name":
			if info.Model == "" {
				info.Model = val
			}
		case "cpu MHz":
			// Last one wins (varies per core); use first occurrence
			if info.SpeedMHz == 0 {
				var mhz float64
				fmt.Sscanf(val, "%f", &mhz)
				info.SpeedMHz = mhz
			}
		case "processor":
			info.Threads++
		case "core id":
			coreSet[val] = true
		}
	}
	info.Cores = len(coreSet)
	if info.Cores == 0 {
		info.Cores = info.Threads
	}
	return info
}

func parseLinuxMemInfo(data string) MemoryInfo {
	var totalKB uint64
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemTotal:"), "%d", &totalKB)
			break
		}
	}
	return MemoryInfo{TotalMB: totalKB / 1024}
}

func parseLinuxLsblk(data []byte) []DiskInfo {
	var result struct {
		Blockdevices []struct {
			Name       string `json:"name"`
			Model      string `json:"model"`
			Serial     string `json:"serial"`
			Type       string `json:"type"`
			Size       string `json:"size"`
			Tran       string `json:"tran"`
			Mountpoint string `json:"mountpoint"`
		} `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	var disks []DiskInfo
	for _, dev := range result.Blockdevices {
		if dev.Type != "disk" {
			continue
		}
		dtype := classifyDisk("", dev.Tran, dev.Model)
		disks = append(disks, DiskInfo{
			Model:     strings.TrimSpace(dev.Model),
			Serial:    strings.TrimSpace(dev.Serial),
			Type:      dtype,
			Interface: strings.ToUpper(dev.Tran),
		})
	}
	return disks
}

func parseLinuxIPAddr(data []byte) []NetworkInfo {
	var ifaces []struct {
		Ifname    string `json:"ifname"`
		Address   string `json:"address"`
		LinkType  string `json:"link_type"`
		AddrInfos []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(data, &ifaces); err != nil {
		return nil
	}
	var result []NetworkInfo
	for _, iface := range ifaces {
		if iface.Ifname == "lo" {
			continue
		}
		var addrs []string
		for _, ai := range iface.AddrInfos {
			if ai.Local != "" {
				addrs = append(addrs, ai.Local)
			}
		}
		result = append(result, NetworkInfo{
			Name:       iface.Ifname,
			MACAddress: iface.Address,
			Addresses:  addrs,
		})
	}
	return result
}

func parseLinuxGPU(lspciOutput string) []GpuInfo {
	var gpus []GpuInfo
	for _, line := range strings.Split(lspciOutput, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vga") || strings.Contains(lower, "3d controller") ||
			strings.Contains(lower, "display controller") {
			// Extract the description after the device class
			idx := strings.Index(line, ": ")
			if idx >= 0 {
				gpus = append(gpus, GpuInfo{Model: strings.TrimSpace(line[idx+2:])})
			}
		}
	}
	return gpus
}

func readLinuxDMI() MotherboardInfo {
	read := func(path string) string {
		out, err := newCmd("cat", path).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return MotherboardInfo{
		Manufacturer: read("/sys/class/dmi/id/board_vendor"),
		Product:      read("/sys/class/dmi/id/board_name"),
		Version:      read("/sys/class/dmi/id/board_version"),
		Serial:       read("/sys/class/dmi/id/board_serial"),
	}
}

// linuxDMIDir: where the kernel exposes the SMBIOS strings.
const linuxDMIDir = "/sys/class/dmi/id"

// linuxDMIRawFiles: the files of linuxDMIDir copied into raw.dmi under their
// own name (chassis_type is the SMBIOS number as text, e.g. "10" = notebook).
var linuxDMIRawFiles = []string{
	"sys_vendor", "product_name", "product_version", "product_family",
	"product_serial", "chassis_type",
}

// readLinuxDMIRaw reads linuxDMIRawFiles from dir: name -> trimmed content,
// files missing, unreadable (product_serial when not root) or blank left out.
func readLinuxDMIRaw(dir string) map[string]interface{} {
	m := map[string]interface{}{}
	for _, f := range linuxDMIRawFiles {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			m[f] = v
		}
	}
	return m
}

func readLinuxBIOS() BiosInfo {
	read := func(path string) string {
		out, err := newCmd("cat", path).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return BiosInfo{
		Vendor:  read("/sys/class/dmi/id/bios_vendor"),
		Version: read("/sys/class/dmi/id/bios_version"),
		Date:    read("/sys/class/dmi/id/bios_date"),
	}
}

func collectLinuxOSDetails() OSDetails {
	od := OSDetails{}
	// /etc/os-release has PRETTY_NAME, VERSION_ID, VERSION
	if out, err := newCmd("cat", "/etc/os-release").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			switch parts[0] {
			case "PRETTY_NAME":
				od.Edition = val
			case "VERSION_ID":
				od.DisplayVersion = val
			case "BUILD_ID":
				od.BuildNumber = val
			}
		}
	}
	if od.BuildNumber == "" {
		if out, err := newCmd("uname", "-r").Output(); err == nil {
			od.BuildNumber = strings.TrimSpace(string(out))
		}
	}
	return od
}

func collectLinuxBattery() *BatteryInfo {
	// Check /sys/class/power_supply/BAT0 (or BAT1)
	for _, name := range []string{"BAT0", "BAT1", "macsmc-battery"} {
		base := "/sys/class/power_supply/" + name
		if _, err := os.Stat(base); err != nil {
			continue
		}
		read := func(f string) string {
			out, err := os.ReadFile(base + "/" + f)
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(out))
		}
		readInt := func(f string) int {
			v := read(f)
			n, _ := strconv.Atoi(v)
			return n
		}

		// Energy values in µWh, convert to mWh
		design := readInt("energy_full_design") / 1000
		full := readInt("energy_full") / 1000
		if design == 0 {
			// Some systems use charge_full_design (µAh) instead
			design = readInt("charge_full_design") / 1000
			full = readInt("charge_full") / 1000
		}
		health := 0.0
		if design > 0 {
			health = float64(full) / float64(design) * 100
		}
		return &BatteryInfo{
			Present:        true,
			DesignCapacity: design,
			FullCapacity:   full,
			HealthPercent:  math.Round(health*10) / 10,
			CycleCount:     readInt("cycle_count"),
			Status:         read("status"),
		}
	}
	return nil
}

// ── macOS ─────────────────────────────────────────────────────────────────────

func scanDarwinInventory(inv *InventoryData) error {
	// system_profiler outputs JSON for each data type.
	types := []string{
		"SPHardwareDataType",
		"SPMemoryDataType",
		"SPStorageDataType",
		"SPNetworkDataType",
		"SPDisplaysDataType",
	}

	out, err := newCmd("system_profiler", append([]string{"-json"}, types...)...).Output()
	if err != nil {
		return fmt.Errorf("system_profiler: %w", err)
	}

	var sp map[string][]map[string]interface{}
	if err := json.Unmarshal(out, &sp); err != nil {
		return fmt.Errorf("parse system_profiler JSON: %w", err)
	}
	inv.Raw["system_profiler"] = sp

	// Hardware (CPU, memory total)
	for _, item := range sp["SPHardwareDataType"] {
		inv.CPU = CpuInfo{
			Model:        stringField(item, "cpu_type"),
			Cores:        intField(item, "number_processors"),
			SpeedMHz:     parseMHzString(stringField(item, "current_processor_speed")),
			Architecture: runtime.GOARCH,
		}
		// Logical processors may be in a separate key
		if tc := intField(item, "packages"); tc > 0 && inv.CPU.Cores == 0 {
			inv.CPU.Cores = tc
		}
		memStr := stringField(item, "physical_memory")
		inv.Memory.TotalMB = parseMemString(memStr)
	}

	// Memory slots
	for _, item := range sp["SPMemoryDataType"] {
		slots, ok := item["_items"].([]interface{})
		if !ok {
			continue
		}
		for _, s := range slots {
			sm, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			sizeMB := parseMemString(stringField(sm, "dimm_size"))
			inv.Memory.Slots = append(inv.Memory.Slots, MemorySlot{
				Slot:         stringField(sm, "dimm_tag"),
				SizeMB:       sizeMB,
				Type:         stringField(sm, "dimm_type"),
				SpeedMHz:     parseSpeedString(stringField(sm, "dimm_speed")),
				Manufacturer: stringField(sm, "dimm_manufacturer"),
			})
		}
	}

	// Storage
	for _, item := range sp["SPStorageDataType"] {
		sizeStr := stringField(item, "size_in_bytes")
		var sizeBytes int64
		fmt.Sscanf(sizeStr, "%d", &sizeBytes)
		mediaType := stringField(item, "spstorage_is_internal")
		iface := stringField(item, "spstorage_interface_type")
		dtype := classifyDisk("", iface, stringField(item, "disk_name"))
		if mediaType == "" {
			mediaType = iface
		}
		inv.Disks = append(inv.Disks, DiskInfo{
			Model:     stringField(item, "disk_name"),
			SizeBytes: sizeBytes,
			Type:      dtype,
			Interface: iface,
		})
	}

	// Network
	for _, item := range sp["SPNetworkDataType"] {
		name := stringField(item, "interface")
		if name == "" {
			name = stringField(item, "_name")
		}
		mac := ""
		if eth, ok := item["Ethernet"].(map[string]interface{}); ok {
			mac = stringField(eth, "MAC Address")
		}
		var addrs []string
		if ipv4, ok := item["IPv4"].(map[string]interface{}); ok {
			if addr := stringField(ipv4, "Addresses"); addr != "" {
				addrs = append(addrs, addr)
			}
		}
		if ipv6, ok := item["IPv6"].(map[string]interface{}); ok {
			if addr := stringField(ipv6, "Addresses"); addr != "" {
				addrs = append(addrs, addr)
			}
		}
		inv.Network = append(inv.Network, NetworkInfo{
			Name:       name,
			MACAddress: mac,
			Addresses:  addrs,
		})
	}

	// GPU
	for _, item := range sp["SPDisplaysDataType"] {
		inv.GPU = append(inv.GPU, GpuInfo{
			Model: stringField(item, "spdisplays_vendor") + " " + stringField(item, "_name"),
			VRAM:  stringField(item, "spdisplays_vram"),
		})
	}

	// OS Details via sw_vers
	if out, err := newCmd("sw_vers").Output(); err == nil {
		od := OSDetails{}
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.TrimSpace(parts[1])
			switch strings.TrimSpace(parts[0]) {
			case "ProductName":
				od.Edition = val
			case "ProductVersion":
				od.DisplayVersion = val
			case "BuildVersion":
				od.BuildNumber = val
			}
		}
		inv.OS = od
	}

	// Printers (CUPS — same subsystem as Linux)
	inv.Printers = scanCupsPrinters()

	// COM/serial ports — list /dev/cu.* (callout devices; canonical for macOS,
	// avoids double-listing the matching /dev/tty.* entry for the same device).
	if entries, err := os.ReadDir("/dev"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "cu.") && !strings.Contains(name, "Bluetooth-Incoming") {
				inv.ComPorts = append(inv.ComPorts, ComPortInfo{Port: "/dev/" + name})
			}
		}
	}

	// Battery via system_profiler SPPowerDataType
	if out, err := newCmd("system_profiler", "-json", "SPPowerDataType").Output(); err == nil {
		var pw map[string][]map[string]interface{}
		if json.Unmarshal(out, &pw) == nil {
			for _, item := range pw["SPPowerDataType"] {
				if bi, ok := item["sppower_battery_health_info"].(map[string]interface{}); ok {
					cycle, _ := strconv.Atoi(fmt.Sprintf("%v", bi["sppower_battery_cycle_count"]))
					maxCap := stringField(bi, "sppower_battery_health_maximum_capacity")
					health := 0.0
					if strings.HasSuffix(maxCap, "%") {
						fmt.Sscanf(maxCap, "%f%%", &health)
					}
					inv.Battery = &BatteryInfo{
						Present:       true,
						CycleCount:    cycle,
						HealthPercent: health,
						Status:        stringField(bi, "sppower_battery_health"),
					}
					break
				}
			}
		}
	}

	return nil
}

// ── FreeBSD ──────────────────────────────────────────────────────────────────

func scanFreeBSDInventory(inv *InventoryData) error {
	// CPU via sysctl
	inv.CPU = CpuInfo{Architecture: runtime.GOARCH}
	if out, err := newCmd("sysctl", "-n", "hw.model").Output(); err == nil {
		inv.CPU.Model = strings.TrimSpace(string(out))
	}
	if out, err := newCmd("sysctl", "-n", "hw.ncpu").Output(); err == nil {
		var n int
		fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
		inv.CPU.Threads = n
		inv.CPU.Cores = n // FreeBSD doesn't easily distinguish cores vs threads via sysctl
	}

	// Memory via sysctl hw.physmem (bytes)
	if out, err := newCmd("sysctl", "-n", "hw.physmem").Output(); err == nil {
		var memBytes uint64
		fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &memBytes)
		inv.Memory.TotalMB = memBytes / (1024 * 1024)
	}

	// Disks via sysctl kern.disks + diskinfo
	inv.Disks = collectFreeBSDDisks()

	// Network interfaces via ifconfig
	if out, err := newCmd("ifconfig").Output(); err == nil {
		inv.Network = parseFreeBSDIfconfig(string(out))
	}

	// GPU — skip (FreeBSD servers typically don't have GPUs)
	inv.GPU = nil

	// Motherboard via kenv
	inv.Motherboard = readFreeBSDMotherboard()

	// BIOS via kenv
	inv.BIOS = readFreeBSDBIOS()

	// OS Details
	inv.OS = collectFreeBSDOSDetails()

	// Battery — nil (FreeBSD servers)
	inv.Battery = nil

	// Printers — best-effort via lpstat (CUPS is uncommon on FreeBSD servers,
	// but harmless to check; scanCupsPrinters returns nil if unavailable).
	inv.Printers = scanCupsPrinters()

	// COM/serial ports — cuau*/uart callout devices and USB-serial ttyU*.
	if entries, err := os.ReadDir("/dev"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "cuau") || strings.HasPrefix(name, "cuaU") {
				inv.ComPorts = append(inv.ComPorts, ComPortInfo{Port: "/dev/" + name})
			}
		}
	}

	return nil
}

func collectFreeBSDDisks() []DiskInfo {
	out, err := newCmd("sysctl", "-n", "kern.disks").Output()
	if err != nil {
		return nil
	}
	diskNames := strings.Fields(strings.TrimSpace(string(out)))
	var disks []DiskInfo
	for _, name := range diskNames {
		di := DiskInfo{Model: name}
		// diskinfo returns: <device> <sectorsize> <size_in_bytes> <sectors>
		if info, err := newCmd("diskinfo", name).Output(); err == nil {
			fields := strings.Fields(strings.TrimSpace(string(info)))
			if len(fields) >= 3 {
				var sizeBytes int64
				fmt.Sscanf(fields[2], "%d", &sizeBytes)
				di.SizeBytes = sizeBytes
			}
		}
		dtype := classifyDisk("", "", name)
		if strings.HasPrefix(name, "nvd") || strings.HasPrefix(name, "nda") {
			dtype = "NVMe"
		} else if strings.HasPrefix(name, "ada") {
			dtype = "SSD" // ATA direct-access (could be HDD too, best guess)
		} else if strings.HasPrefix(name, "da") {
			dtype = "HDD"
		}
		di.Type = dtype
		disks = append(disks, di)
	}
	return disks
}

func parseFreeBSDIfconfig(data string) []NetworkInfo {
	var result []NetworkInfo
	var current *NetworkInfo
	for _, line := range strings.Split(data, "\n") {
		if len(line) > 0 && line[0] != '\t' && line[0] != ' ' {
			// New interface line, e.g. "em0: flags=8843<UP,BROADCAST,..."
			if current != nil && current.Name != "lo0" {
				result = append(result, *current)
			}
			parts := strings.SplitN(line, ":", 2)
			current = &NetworkInfo{Name: strings.TrimSpace(parts[0])}
		} else if current != nil {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "ether ") {
				current.MACAddress = strings.TrimPrefix(trimmed, "ether ")
			} else if strings.HasPrefix(trimmed, "inet ") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					current.Addresses = append(current.Addresses, fields[1])
				}
			} else if strings.HasPrefix(trimmed, "inet6 ") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					addr := fields[1]
					// Remove %scope suffix if present
					if idx := strings.Index(addr, "%"); idx >= 0 {
						addr = addr[:idx]
					}
					current.Addresses = append(current.Addresses, addr)
				}
			}
		}
	}
	if current != nil && current.Name != "lo0" {
		result = append(result, *current)
	}
	return result
}

func readFreeBSDMotherboard() MotherboardInfo {
	kenv := func(key string) string {
		out, err := newCmd("kenv", key).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return MotherboardInfo{
		Manufacturer: kenv("smbios.planar.maker"),
		Product:      kenv("smbios.planar.product"),
		Version:      kenv("smbios.planar.version"),
		Serial:       kenv("smbios.planar.serial"),
	}
}

func readFreeBSDBIOS() BiosInfo {
	kenv := func(key string) string {
		out, err := newCmd("kenv", key).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return BiosInfo{
		Vendor:  kenv("smbios.bios.vendor"),
		Version: kenv("smbios.bios.version"),
		Date:    kenv("smbios.bios.reldate"),
	}
}

func collectFreeBSDOSDetails() OSDetails {
	od := OSDetails{}
	// freebsd-version gives the userland version
	if out, err := newCmd("freebsd-version").Output(); err == nil {
		ver := strings.TrimSpace(string(out))
		od.Edition = "FreeBSD " + ver
		od.DisplayVersion = ver
	}
	// uname -r for kernel build
	if out, err := newCmd("uname", "-r").Output(); err == nil {
		od.BuildNumber = strings.TrimSpace(string(out))
	}
	return od
}

func scanFreeBSDSoftware() []SoftwareEntry {
	var entries []SoftwareEntry

	// pkg query for installed packages: name|version|maintainer
	if out, err := newCmd("pkg", "query", "%n|%v|%m").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
			if len(parts) >= 2 && parts[0] != "" {
				entries = append(entries, SoftwareEntry{
					Name:      parts[0],
					Version:   parts[1],
					Publisher: safeGet(parts, 2),
					Source:    "pkg",
				})
			}
		}
	}

	return entries
}

// ── Software scanning ─────────────────────────────────────────────────────────

// scanBitLocker retrieves BitLocker status and recovery keys for all volumes.
// Requires admin privileges (agent runs as SYSTEM).
//
// PowerShell 3+ with the BitLocker module (Windows 8 / Server 2012+ with the
// feature): Get-BitLockerVolume, as before. Otherwise (Windows 7 / 2008 R2 =
// PowerShell 2.0, or no BitLocker module): the same data straight from WMI
// Win32_EncryptableVolume, mapped to the same strings (pscompat.go).
func scanBitLocker() []BitLockerVolume {
	if psAtLeast(3) {
		vols, noModule := scanBitLockerCmdlet()
		if !noModule {
			return vols
		}
	}
	out, err := runPS(bitLockerWMIScript)
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseBitLockerWMIOutput(string(out))
}

// scanBitLockerCmdlet is the Get-BitLockerVolume path; noModule=true when the
// BitLocker module is not available on this machine.
func scanBitLockerCmdlet() (vols []BitLockerVolume, noModule bool) {
	out, err := runPS(`if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { '` + bitLockerNoModuleMarker + `'; exit 0 }
$vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
if (-not $vols) { exit 0 }
$result = @()
foreach ($v in $vols) {
  $keys = @()
  foreach ($p in $v.KeyProtector) {
    if ($p.KeyProtectorType -eq 'RecoveryPassword' -and $p.RecoveryPassword) {
      $keys += $p.RecoveryPassword
    }
  }
  $result += [PSCustomObject]@{
    driveLetter          = $v.MountPoint
    status               = $v.VolumeStatus.ToString()
    protectionStatus     = $v.ProtectionStatus.ToString()
    encryptionPercentage = $v.EncryptionPercentage
    recoveryKeys         = $keys
  }
}
$result | ConvertTo-Json -Compress`)
	if err != nil {
		return nil, false
	}

	raw := strings.TrimSpace(strings.TrimPrefix(string(out), utf8BOM))
	if raw == bitLockerNoModuleMarker {
		return nil, true
	}
	if raw == "" {
		return nil, false
	}

	// PowerShell returns a single object (not array) when there's only one volume
	var volumes []BitLockerVolume
	if strings.HasPrefix(raw, "[") {
		json.Unmarshal([]byte(raw), &volumes)
	} else {
		var single BitLockerVolume
		if json.Unmarshal([]byte(raw), &single) == nil {
			volumes = []BitLockerVolume{single}
		}
	}
	return volumes, false
}

func scanInstalledSoftware() []SoftwareEntry {
	switch runtime.GOOS {
	case "windows":
		return scanWindowsSoftware()
	case "linux":
		return scanLinuxSoftware()
	case "darwin":
		return scanDarwinSoftware()
	case "freebsd":
		return scanFreeBSDSoftware()
	}
	return nil
}

// scanWindowsSoftware lists installed software from the registry Uninstall
// keys, natively (no PowerShell): HKLM 64-bit, HKLM WOW6432Node, HKCU — the
// same sources, filter and de-duplication as the former PowerShell script
// (see buildWindowsSoftwareList).
func scanWindowsSoftware() []SoftwareEntry {
	recs, err := collectUninstallRecords()
	if err != nil {
		log.Printf("Software scan (registry) error: %v", err)
		return nil
	}
	return buildWindowsSoftwareList(recs)
}

func scanLinuxSoftware() []SoftwareEntry {
	var entries []SoftwareEntry

	// dpkg (Debian/Ubuntu)
	if out, err := newCmd("dpkg-query", "-W", "-f=${Package}|${Version}|${Maintainer}\n").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
			if len(parts) >= 2 && parts[0] != "" {
				entries = append(entries, SoftwareEntry{
					Name:      parts[0],
					Version:   parts[1],
					Publisher: safeGet(parts, 2),
					Source:    "dpkg",
				})
			}
		}
	}

	// rpm (RHEL/CentOS/Fedora)
	if len(entries) == 0 {
		if out, err := newCmd("rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{VENDOR}\n").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
				if len(parts) >= 2 && parts[0] != "" {
					entries = append(entries, SoftwareEntry{
						Name:      parts[0],
						Version:   parts[1],
						Publisher: safeGet(parts, 2),
						Source:    "rpm",
					})
				}
			}
		}
	}

	// flatpak
	if out, err := newCmd("flatpak", "list", "--app", "--columns=application,version,origin").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				e := SoftwareEntry{Source: "flatpak", PackageID: parts[0]}
				if len(parts) >= 2 {
					e.Version = parts[1]
				}
				e.Name = parts[0]
				entries = append(entries, e)
			}
		}
	}

	// snap
	if out, err := newCmd("snap", "list").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] { // skip header
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				entries = append(entries, SoftwareEntry{
					Name:    parts[0],
					Version: parts[1],
					Source:  "snap",
				})
			}
		}
	}

	return entries
}

func scanDarwinSoftware() []SoftwareEntry {
	var entries []SoftwareEntry

	// Applications from /Applications
	if out, err := newCmd("ls", "/Applications").Output(); err == nil {
		for _, app := range strings.Split(string(out), "\n") {
			app = strings.TrimSpace(app)
			if strings.HasSuffix(app, ".app") {
				name := strings.TrimSuffix(app, ".app")
				entries = append(entries, SoftwareEntry{Name: name, Source: "applications"})
			}
		}
	}

	// Homebrew
	if out, err := newCmd("brew", "list", "--versions").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) >= 2 {
				entries = append(entries, SoftwareEntry{
					Name:      parts[0],
					Version:   parts[len(parts)-1],
					Source:    "homebrew",
					PackageID: parts[0],
				})
			}
		}
	}

	// mas (Mac App Store)
	if out, err := newCmd("mas", "list").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Format: "1234567890 App Name (1.0)"
			spaceIdx := strings.Index(line, " ")
			if spaceIdx < 0 {
				continue
			}
			rest := strings.TrimSpace(line[spaceIdx+1:])
			version := ""
			if parenOpen := strings.LastIndex(rest, "("); parenOpen >= 0 {
				version = strings.Trim(rest[parenOpen:], "()")
				rest = strings.TrimSpace(rest[:parenOpen])
			}
			entries = append(entries, SoftwareEntry{
				Name:      rest,
				Version:   version,
				Source:    "mas",
				PackageID: strings.TrimSpace(line[:spaceIdx]),
			})
		}
	}

	return entries
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func classifyDisk(mediaType, iface, model string) string {
	lower := strings.ToLower(model + " " + mediaType + " " + iface)
	if strings.Contains(lower, "nvme") {
		return "NVMe"
	}
	if strings.Contains(lower, "ssd") || strings.Contains(lower, "solid") {
		return "SSD"
	}
	if strings.Contains(lower, "usb") {
		return "USB"
	}
	if strings.Contains(lower, "hdd") || strings.Contains(lower, "hard disk") || strings.Contains(lower, "sata") {
		return "HDD"
	}
	return "Unknown"
}

func parseMHzString(s string) float64 {
	// "2.4 GHz" → 2400, "1200 MHz" → 1200
	s = strings.TrimSpace(s)
	var val float64
	var unit string
	fmt.Sscanf(s, "%f %s", &val, &unit)
	if strings.ToLower(unit) == "ghz" {
		return val * 1000
	}
	return val
}

func parseMemString(s string) uint64 {
	// "8 GB" → 8192, "512 MB" → 512
	s = strings.TrimSpace(s)
	var val float64
	var unit string
	fmt.Sscanf(s, "%f %s", &val, &unit)
	switch strings.ToUpper(unit) {
	case "GB":
		return uint64(val * 1024)
	case "TB":
		return uint64(val * 1024 * 1024)
	default:
		return uint64(val)
	}
}

func parseSpeedString(s string) int {
	// "2400 MHz" → 2400
	var val int
	fmt.Sscanf(s, "%d", &val)
	return val
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func intField(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case int64:
			return int(n)
		}
	}
	return 0
}

func int64Field(m map[string]interface{}, key string) int64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int:
			return int64(n)
		case int64:
			return n
		}
	}
	return 0
}

func float64Field(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case int64:
			return float64(n)
		}
	}
	return 0
}

func safeGet(parts []string, idx int) string {
	if idx < len(parts) {
		return parts[idx]
	}
	return ""
}
