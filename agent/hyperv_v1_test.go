package main

import (
	"errors"
	"testing"
)

// Rows as root\virtualization (Server 2008 R2 SP1) reports them: the host's
// own Msvm_ComputerSystem (Name = host name) mixed with the VMs, settings of
// the active configuration ("Microsoft:<VM GUID>\...") and of a snapshot
// ("Microsoft:<snapshot GUID>\..."), uint64 as strings, uint16 as int32.
func TestBuildHyperVVMsV1(t *testing.T) {
	const vm1 = "5A2D6C1E-0F3B-4C3A-9E8D-1B2C3D4E5F60"
	const vm2 = "0B9A8C7D-6E5F-4A3B-8C2D-1E0F9A8B7C6D"
	const snapA = "11111111-2222-3333-4444-555555555555"
	const snapB = "66666666-7777-8888-9999-AAAAAAAAAAAA"
	s := hvV1Snapshot{
		VMs: []wmiRow{
			{"Name": "HV-HOST01", "ElementName": "HV-HOST01", "EnabledState": int32(2)},
			{"Name": vm1, "ElementName": "DC01", "EnabledState": int32(2), "OnTimeInMilliseconds": "3723000"},
			{"Name": vm2, "ElementName": "Old app", "EnabledState": int32(32769), "OnTimeInMilliseconds": "0"},
		},
		Snapshots: []wmiRow{
			{"InstanceID": "Microsoft:" + snapB, "SystemName": vm1, "ElementName": "after update", "CreationTime": "20240302101500.000000+060",
				"Parent": `\\HV-HOST01\root\virtualization:Msvm_VirtualSystemSettingData.InstanceID="Microsoft:` + snapA + `"`},
			{"InstanceID": "Microsoft:" + snapA, "SystemName": vm1, "ElementName": "before update", "CreationTime": "20240301080000.000000+000"},
		},
		Processors: []wmiRow{
			{"InstanceID": `Microsoft:` + vm1 + `\b637f346-6a0e-4dec-af52-bd70cb80a21d\0`, "VirtualQuantity": "4"},
			{"InstanceID": `Microsoft:` + snapA + `\b637f346-6a0e-4dec-af52-bd70cb80a21d\0`, "VirtualQuantity": "2"},
			{"InstanceID": `Microsoft:` + vm2 + `\b637f346-6a0e-4dec-af52-bd70cb80a21d\0`, "VirtualQuantity": "1"},
		},
		Memory: []wmiRow{
			{"InstanceID": `Microsoft:` + vm1 + `\4764334d-e001-4176-82ee-5594ec9b530e`, "VirtualQuantity": "4096", "DynamicMemoryEnabled": true},
			{"InstanceID": `Microsoft:` + vm2 + `\4764334d-e001-4176-82ee-5594ec9b530e`, "VirtualQuantity": "1024"},
		},
		NICs: []wmiRow{
			{"InstanceID": `Microsoft:` + vm1 + `\C8BD2E8B-1A1B-4F3C-9A2B-1C2D3E4F5A6B`, "Address": "00155D010203"},
			{"InstanceID": `Microsoft:` + vm2 + `\AAAABBBB-1A1B-4F3C-9A2B-1C2D3E4F5A6B`, "Address": "000000000000"},
		},
	}
	vms := buildHyperVVMsV1(s)
	if len(vms) != 2 {
		t.Fatalf("got %d VMs: %+v", len(vms), vms)
	}
	a, b := vms[0], vms[1]
	if a.VMId != "5a2d6c1e-0f3b-4c3a-9e8d-1b2c3d4e5f60" || a.Name != "DC01" || a.State != "running" || a.RawState != "Running" ||
		a.CPUCount != 4 || a.MemoryBytes != 4096*1024*1024 || !a.DynamicMemory || a.UptimeSeconds != 3723 || a.Generation != 1 {
		t.Errorf("vm1 = %+v", a)
	}
	if len(a.MACAddresses) != 1 || a.MACAddresses[0] != "00:15:5D:01:02:03" || a.IPAddresses == nil {
		t.Errorf("vm1 nics = %v %v", a.MACAddresses, a.IPAddresses)
	}
	if a.CheckpointCount != 2 || a.Checkpoints[0].Name != "before update" || a.Checkpoints[0].CreatedAt != "2024-03-01T08:00:00Z" ||
		a.Checkpoints[1].ParentName != "before update" || a.Checkpoints[1].CreatedAt != "2024-03-02T09:15:00Z" {
		t.Errorf("vm1 checkpoints = %+v", a.Checkpoints)
	}
	if b.State != "saved" || b.MemoryBytes != 0 || b.UptimeSeconds != 0 || b.CPUCount != 1 || len(b.MACAddresses) != 0 || b.Checkpoints == nil {
		t.Errorf("vm2 = %+v", b)
	}
}

func TestHyperVV1Helpers(t *testing.T) {
	for action, want := range map[string]int32{"start": 2, "resume": 2, "stop": 3, "restart": 10, "pause": 32768, "save": 32769} {
		if got, ok := hyperVV1RequestedState(action); !ok || got != want {
			t.Errorf("%s -> %d %v", action, got, ok)
		}
	}
	if _, ok := hyperVV1RequestedState("shutdown"); ok {
		t.Error("shutdown is not a state change")
	}
	if hyperVV1ReturnError(0) != nil || hyperVV1ReturnError(4096) != nil || hyperVV1ReturnError(32775) == nil {
		t.Error("return values")
	}
	if validVMGUID("x' OR Name LIKE '%") || !validVMGUID("5A2D6C1E-0F3B-4C3A-9E8D-1B2C3D4E5F60") {
		t.Error("validVMGUID")
	}
	if dmtfToISO("garbage") != "" || dmtfToISO("20240301080000.500000-120") != "2024-03-01T10:00:00.5Z" {
		t.Errorf("dmtf = %q", dmtfToISO("20240301080000.500000-120"))
	}
	if !errors.Is(errHyperVV1Unsupported, errHyperVV1Unsupported) || hyperVV1StateName(3) != "Off" {
		t.Error("misc")
	}
}
