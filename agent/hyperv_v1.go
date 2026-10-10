package main

// Hyper-V on Windows Server 2008 R2: no Hyper-V PowerShell module (it came
// with Server 2012) and PowerShell 2.0 only, so the VMs are read straight
// from the WMI v1 provider (root\virtualization) — hyperv_v1_windows.go does
// the COM calls, this file turns the recorded rows into HyperVVM values
// (platform-independent, unit-tested).
//
// Supported there: listing (state, uptime, CPU, memory, checkpoints, MACs)
// and power actions (start / stop / shutdown / restart / save / pause /
// resume). Checkpoint management, edit, create, delete and the console
// thumbnail answer errHyperVV1Unsupported — a clean, final error (no retry
// loop on the server side).

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errHyperVV1Unsupported = errors.New("not supported on Windows Server 2008 R2 (Hyper-V WMI v1): use Hyper-V Manager on the host")

// hvV1Snapshot: rows read from root\virtualization.
type hvV1Snapshot struct {
	VMs        []wmiRow // Msvm_ComputerSystem WHERE Caption='Virtual Machine': Name, ElementName, EnabledState, OnTimeInMilliseconds
	Snapshots  []wmiRow // Msvm_VirtualSystemSettingData WHERE SettingType=5: InstanceID, SystemName, ElementName, CreationTime, Parent
	Processors []wmiRow // Msvm_ProcessorSettingData: InstanceID, VirtualQuantity
	Memory     []wmiRow // Msvm_MemorySettingData: InstanceID, VirtualQuantity, DynamicMemoryEnabled
	NICs       []wmiRow // Msvm_SyntheticEthernetPortSettingData + Msvm_EmulatedEthernetPortSettingData: InstanceID, Address
}

// hyperVV1StateName: Msvm_ComputerSystem.EnabledState (v1) -> the State name
// Get-VM prints, so normaliseVMState maps both paths alike.
func hyperVV1StateName(s int64) string {
	switch s {
	case 2:
		return "Running"
	case 3:
		return "Off"
	case 32768:
		return "Paused"
	case 32769:
		return "Saved"
	case 32770:
		return "Starting"
	case 32771:
		return "Snapshotting"
	case 32773:
		return "Saving"
	case 32774:
		return "Stopping"
	case 32776:
		return "Pausing"
	case 32777:
		return "Resuming"
	}
	return "Other"
}

// hyperVV1RequestedState: action -> Msvm_ComputerSystem.RequestStateChange
// argument (v1). "shutdown" is not a state change (Msvm_ShutdownComponent).
func hyperVV1RequestedState(action string) (int32, bool) {
	switch action {
	case "start", "resume":
		return 2, true // Enabled
	case "stop":
		return 3, true // Disabled = hard power off (Stop-VM -TurnOff)
	case "restart":
		return 10, true // Reboot = hard reset (Restart-VM -Force)
	case "pause":
		return 32768, true
	case "save":
		return 32769, true // Suspended = saved state
	}
	return 0, false
}

// hyperVV1ReturnError explains a non-success ReturnValue of a v1 method.
// 0 = completed, 4096 = job started (asynchronous, accepted).
func hyperVV1ReturnError(rv int64) error {
	switch rv {
	case 0, 4096:
		return nil
	case 32775:
		return fmt.Errorf("invalid state for this operation (rv=32775)")
	case 32768:
		return fmt.Errorf("failed (rv=32768)")
	case 32769:
		return fmt.Errorf("access denied (rv=32769)")
	case 32773:
		return fmt.Errorf("invalid parameter (rv=32773)")
	case 32774:
		return fmt.Errorf("system in use (rv=32774)")
	}
	return fmt.Errorf("failed (rv=%d)", rv)
}

var reVMGUID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// validVMGUID: the vmId is interpolated in WQL — only a bare GUID is accepted.
func validVMGUID(id string) bool { return reVMGUID.MatchString(id) }

// dmtfToISO converts a CIM datetime ("20100314153010.123456-060") to an
// RFC 3339 UTC string ("" when unparsable).
func dmtfToISO(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 25 || s[14] != '.' {
		return ""
	}
	t, err := time.Parse("20060102150405", s[:14])
	if err != nil {
		return ""
	}
	off, err := strconv.Atoi(s[22:25])
	if err != nil {
		return ""
	}
	if s[21] == '-' {
		off = -off
	} else if s[21] != '+' {
		return ""
	}
	micro, _ := strconv.Atoi(s[15:21])
	t = t.Add(time.Duration(micro) * time.Microsecond).Add(-time.Duration(off) * time.Minute)
	return t.UTC().Format(time.RFC3339Nano)
}

// reInstanceIDInPath extracts InstanceID="..." from a WMI object path.
var reInstanceIDInPath = regexp.MustCompile(`(?i)InstanceID="([^"]*)"`)

// v1OwnerGUID: "Microsoft:<GUID>\..." -> upper-case GUID ("" otherwise).
func v1OwnerGUID(instanceID string) string {
	rest := instanceID
	if i := strings.Index(rest, ":"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.IndexAny(rest, `\/`); i >= 0 {
		rest = rest[:i]
	}
	if !validVMGUID(rest) {
		return ""
	}
	return strings.ToUpper(rest)
}

// buildHyperVVMsV1 assembles the VM list from the v1 rows. Component settings
// (CPU, memory, NICs) belong to the ACTIVE configuration when their
// InstanceID starts with "Microsoft:<VM GUID>\" (snapshot copies carry the
// snapshot's GUID instead).
func buildHyperVVMsV1(s hvV1Snapshot) []HyperVVM {
	cpuByVM := map[string]int64{}
	for _, r := range s.Processors {
		if g := v1OwnerGUID(r.str("InstanceID")); g != "" {
			cpuByVM[g] = r.int64v("VirtualQuantity")
		}
	}
	memByVM := map[string]wmiRow{}
	for _, r := range s.Memory {
		if g := v1OwnerGUID(r.str("InstanceID")); g != "" {
			memByVM[g] = r
		}
	}
	macsByVM := map[string][]string{}
	for _, r := range s.NICs {
		if g := v1OwnerGUID(r.str("InstanceID")); g != "" {
			if a := r.str("Address"); a != "" {
				macsByVM[g] = append(macsByVM[g], a)
			}
		}
	}
	snapName := map[string]string{} // snapshot InstanceID (upper) -> name
	for _, r := range s.Snapshots {
		snapName[strings.ToUpper(r.str("InstanceID"))] = r.str("ElementName")
	}
	snapsByVM := map[string][]HyperVCheckpoint{}
	for _, r := range s.Snapshots {
		g := strings.ToUpper(r.str("SystemName"))
		parent := ""
		if m := reInstanceIDInPath.FindStringSubmatch(r.str("Parent")); m != nil {
			parent = snapName[strings.ToUpper(strings.ReplaceAll(m[1], `\\`, `\`))]
		}
		snapsByVM[g] = append(snapsByVM[g], HyperVCheckpoint{
			Name:       r.str("ElementName"),
			CreatedAt:  dmtfToISO(r.str("CreationTime")),
			ParentName: parent,
		})
	}

	vms := make([]HyperVVM, 0, len(s.VMs))
	for _, r := range s.VMs {
		g := strings.ToUpper(r.str("Name"))
		if !validVMGUID(g) {
			continue // the host's own Msvm_ComputerSystem
		}
		raw := hyperVV1StateName(r.int64v("EnabledState"))
		state := normaliseVMState(raw)
		var mem int64
		dyn := false
		if m, ok := memByVM[g]; ok {
			dyn = m.boolv("DynamicMemoryEnabled")
			if state == "running" || state == "paused" {
				mem = m.int64v("VirtualQuantity") * 1024 * 1024 // MB
			}
		}
		var uptime int64
		if state == "running" || state == "paused" {
			uptime = r.int64v("OnTimeInMilliseconds") / 1000
		}
		cps := snapsByVM[g]
		if cps == nil {
			cps = []HyperVCheckpoint{}
		}
		sort.SliceStable(cps, func(i, j int) bool { return cps[i].CreatedAt < cps[j].CreatedAt })
		vms = append(vms, HyperVVM{
			VMId:            strings.ToLower(g),
			Name:            r.str("ElementName"),
			State:           state,
			RawState:        raw,
			CPUCount:        int(cpuByVM[g]),
			MemoryBytes:     mem,
			UptimeSeconds:   uptime,
			CheckpointCount: len(cps),
			Checkpoints:     cps,
			IPAddresses:     []string{},
			MACAddresses:    normaliseMACs(macsByVM[g]),
			Generation:      1, // 2008 R2 knows generation-1 VMs only
			DynamicMemory:   dyn,
		})
	}
	return vms
}
