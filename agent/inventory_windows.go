//go:build windows
// +build windows

package main

// Native collection of the Windows inventory (WMI through COM + registry),
// replacing the former PowerShell script that ended with ConvertTo-Json —
// absent from PowerShell 2.0 (Windows 7 / Server 2008 R2), which made the
// whole inventory fail there. Same classes, same properties, same filters as
// the script; the shaping lives in inventory_winbuild.go (unit-tested).

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// wmiInventoryTimeout bounds the whole native WMI pass (a corrupt repository
// can block a COM call for ever; the old script had no bound at all).
const wmiInventoryTimeout = 3 * time.Minute

// portsClassGUID is the "Ports (COM & LPT)" device setup class. The script
// filtered on PNPClass='Ports', a Win32_PnPEntity property added in Windows
// 10: the class GUID selects the same devices on every version.
const portsClassGUID = "{4D36E978-E325-11CE-BFC1-08002BE10318}"

func collectWindowsInventorySnapshot() (winInvSnapshot, error) {
	var s winInvSnapshot
	err := withWMI(wmiInventoryTimeout, func(w *wmiSession) error {
		// The default namespace must answer; everything else is best effort
		// (the script ran with -ErrorAction SilentlyContinue).
		if _, err := w.service(""); err != nil {
			return err
		}
		q := func(ns, wql string, props ...string) []wmiRow {
			rows, err := w.query(ns, wql, props...)
			if err != nil {
				log.Printf("Inventory: %v", err)
				return nil
			}
			return rows
		}
		s.CPU = q("", "SELECT Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,AddressWidth FROM Win32_Processor",
			"Name", "NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed", "AddressWidth")
		if len(s.CPU) == 0 {
			// NumberOfCores / NumberOfLogicalProcessors are missing on a
			// Windows 7 / 2008 R2 lacking KB932370-era updates: retry without.
			s.CPU = q("", "SELECT * FROM Win32_Processor",
				"Name", "NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed", "AddressWidth")
		}
		s.Memory = q("", "SELECT * FROM Win32_PhysicalMemory",
			"DeviceLocator", "Capacity", "MemoryType", "Speed", "Manufacturer")
		s.OS = q("", "SELECT Caption,Version,TotalVisibleMemorySize FROM Win32_OperatingSystem",
			"Caption", "Version", "TotalVisibleMemorySize")
		s.Disks = q("", "SELECT * FROM Win32_DiskDrive",
			"Model", "SerialNumber", "Size", "MediaType", "InterfaceType")
		s.NICs = q("", "SELECT Description,MACAddress,IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE",
			"Description", "MACAddress", "IPAddress")
		s.GPUs = q("", "SELECT Caption,AdapterRAM,DriverVersion,PNPDeviceID FROM Win32_VideoController",
			"Caption", "AdapterRAM", "DriverVersion", "PNPDeviceID")
		s.Board = q("", "SELECT Manufacturer,Product,Version,SerialNumber FROM Win32_BaseBoard",
			"Manufacturer", "Product", "Version", "SerialNumber")
		s.BIOS = q("", "SELECT Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber FROM Win32_BIOS",
			"Manufacturer", "SMBIOSBIOSVersion", "ReleaseDate", "SerialNumber")
		// The machine itself (not its board): maker, model, family, chassis
		// kind. SystemFamily does not exist before Windows 10 / Server 2016
		// (a named SELECT would fail there): SELECT * and read what is there.
		s.System = q("", "SELECT * FROM Win32_ComputerSystem",
			"Manufacturer", "Model", "SystemFamily", "PCSystemType")
		// Version: Lenovo's commercial name ("ThinkPad T14 Gen 3") while
		// Model holds the machine type ("21AH00BXFR").
		s.Product = q("", "SELECT Version FROM Win32_ComputerSystemProduct", "Version")
		s.Printers = q("", "SELECT Name,DriverName,PortName,Default,Network,Shared,PrinterStatus FROM Win32_Printer",
			"Name", "DriverName", "PortName", "Default", "Network", "Shared", "PrinterStatus")
		s.Ports = q("", "SELECT Caption,PNPDeviceID FROM Win32_PnPEntity WHERE ClassGuid = '"+portsClassGUID+"'",
			"Caption", "PNPDeviceID")

		// Windows product key: OA3 (firmware) key; the property does not exist
		// before Windows 8 -> the query fails -> registry backup key.
		if rows, err := w.query("", "SELECT OA3xOriginalProductKey FROM SoftwareLicensingService", "OA3xOriginalProductKey"); err == nil {
			s.OA3Key = firstRow(rows).str("OA3xOriginalProductKey")
		}
		// Office key (last 5) through the Software Protection Platform.
		s.OfficeOSPP = q("", "SELECT PartialProductKey,Name FROM SoftwareLicensingProduct WHERE ApplicationId='0ff1ce15-a989-479d-af46-f275c6370663' AND PartialProductKey IS NOT NULL",
			"PartialProductKey", "Name")

		s.Battery = q("", "SELECT BatteryStatus FROM Win32_Battery", "BatteryStatus")
		if len(s.Battery) > 0 {
			s.BatteryDesigned = q(`root\WMI`, "SELECT DesignedCapacity FROM BatteryStaticData", "DesignedCapacity")
			s.BatteryFullCharged = q(`root\WMI`, "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity", "FullChargedCapacity")
			s.BatteryCycles = q(`root\WMI`, "SELECT CycleCount FROM BatteryCycleCount", "CycleCount")
		}

		// TPM (needs admin — the agent runs as LocalSystem). ManufacturerIdTxt
		// does not exist on Windows 7: SELECT * and read what is there.
		if rows, err := w.query(`root\cimv2\Security\MicrosoftTpm`, "SELECT * FROM Win32_Tpm",
			"ManufacturerIdTxt", "PhysicalPresenceVersionInfo", "SpecVersion",
			"IsActivated_InitialValue", "IsEnabled_InitialValue", "IsOwned_InitialValue"); err == nil {
			s.TPM = rows
		}
		return nil
	})
	if err != nil {
		return s, err
	}

	// Registry (64-bit view, also from the x86 agent on a 64-bit OS).
	s.DisplayVersion = regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "DisplayVersion")
	s.BackupProductKey = regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform`, "BackupProductKeyDefault")
	for _, p := range officeRegistryPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		s.Office = append(s.Office, officeRegProps{
			ProductReleaseIds:     regValueText(k, "ProductReleaseIds"),
			ClientVersionToReport: regValueText(k, "ClientVersionToReport"),
		})
		k.Close()
	}
	return s, nil
}

// regString reads one value (64-bit view) as text; "" when missing.
func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	return regValueText(k, name)
}

// regValueText returns a registry value as Get-ItemProperty showed it once
// interpolated in a string: REG_SZ as is, REG_EXPAND_SZ expanded, numbers in
// decimal, REG_MULTI_SZ joined with spaces. "" when missing / unreadable.
func regValueText(k registry.Key, name string) string {
	_, typ, err := k.GetValue(name, nil)
	if err != nil {
		return ""
	}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return ""
		}
		if typ == registry.EXPAND_SZ {
			if e, err := registry.ExpandString(s); err == nil {
				s = e
			}
		}
		return s
	case registry.DWORD, registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return ""
		}
		return strconv.FormatUint(n, 10)
	case registry.MULTI_SZ:
		v, _, err := k.GetStringsValue(name)
		if err != nil {
			return ""
		}
		return strings.Join(v, " ")
	}
	return ""
}

// ── Installed software ────────────────────────────────────────────────────────

// uninstallSources: the three locations the former script read, with the
// registry view made explicit — HKLM 64-bit, HKLM WOW6432Node (32-bit apps)
// and HKCU. From the x86 agent on a 64-bit OS the old 32-bit PowerShell saw
// only the 32-bit view (twice); the explicit 64-bit view fixes that. On a
// 32-bit OS WOW6432Node does not exist and is skipped.
var uninstallSources = []struct {
	root registry.Key
	path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
}

func collectUninstallRecords() ([]uninstallRecord, error) {
	var recs []uninstallRecord
	opened := 0
	for _, src := range uninstallSources {
		k, err := registry.OpenKey(src.root, src.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		opened++
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			recs = append(recs, uninstallRecord{
				DisplayName:     regValueText(sk, "DisplayName"),
				DisplayVersion:  regValueText(sk, "DisplayVersion"),
				Publisher:       regValueText(sk, "Publisher"),
				InstallDate:     regValueText(sk, "InstallDate"),
				InstallLocation: regValueText(sk, "InstallLocation"),
			})
			sk.Close()
		}
		k.Close()
	}
	if opened == 0 {
		return nil, fmt.Errorf("no Uninstall registry key could be opened")
	}
	return recs, nil
}

// ── Identity helpers (machine_uuid_windows.go) ────────────────────────────────

// wmiMachineUUID: Win32_ComputerSystemProduct.UUID (the value Get-CimInstance
// and `wmic csproduct get UUID` print).
func wmiMachineUUID() string {
	var uuid string
	_ = withWMI(30*time.Second, func(w *wmiSession) error {
		rows, err := w.query("", "SELECT UUID FROM Win32_ComputerSystemProduct", "UUID")
		if err == nil {
			uuid = strings.TrimSpace(firstRow(rows).str("UUID"))
		}
		return err
	})
	return uuid
}

// wmiDiskSerialByIndex: Win32_DiskDrive.SerialNumber of the disk with this
// Index (the value `wmic diskdrive where Index=N get SerialNumber` prints),
// trimmed. ok=false when WMI could not be queried at all.
func wmiDiskSerialByIndex(index int) (serial string, ok bool) {
	err := withWMI(30*time.Second, func(w *wmiSession) error {
		rows, err := w.query("", fmt.Sprintf("SELECT SerialNumber FROM Win32_DiskDrive WHERE Index = %d", index), "SerialNumber")
		if err == nil {
			serial = strings.TrimSpace(firstRow(rows).str("SerialNumber"))
		}
		return err
	})
	return serial, err == nil
}
