//go:build windows

package main

// Hyper-V WMI v1 (root\virtualization) access for Windows Server 2008 R2 —
// see hyperv_v1.go.

import (
	"fmt"
	"strings"
	"time"

	ole "github.com/go-ole/go-ole"
)

const hyperVV1Namespace = `root\virtualization`

// hyperVUsesWMIv1: Windows Server 2008 / 2008 R2 (NT 6.0 / 6.1) have no
// Hyper-V PowerShell module; Server 2012 (6.2) and later use the cmdlets.
func hyperVUsesWMIv1() bool {
	major, minor, _ := windowsOSVersion()
	return major == 6 && minor <= 1
}

func enumerateHyperVVMsV1() ([]HyperVVM, error) {
	var snap hvV1Snapshot
	err := withWMI(2*time.Minute, func(w *wmiSession) error {
		var err error
		snap.VMs, err = w.query(hyperVV1Namespace,
			"SELECT Name,ElementName,EnabledState,OnTimeInMilliseconds FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'",
			"Name", "ElementName", "EnabledState", "OnTimeInMilliseconds")
		if err != nil {
			return err // namespace missing / provider broken: a real error
		}
		opt := func(wql string, props ...string) []wmiRow {
			rows, _ := w.query(hyperVV1Namespace, wql, props...)
			return rows
		}
		snap.Snapshots = opt("SELECT InstanceID,SystemName,ElementName,CreationTime,Parent FROM Msvm_VirtualSystemSettingData WHERE SettingType=5",
			"InstanceID", "SystemName", "ElementName", "CreationTime", "Parent")
		snap.Processors = opt("SELECT InstanceID,VirtualQuantity FROM Msvm_ProcessorSettingData", "InstanceID", "VirtualQuantity")
		// DynamicMemoryEnabled exists from 2008 R2 SP1 only: SELECT *.
		snap.Memory = opt("SELECT * FROM Msvm_MemorySettingData", "InstanceID", "VirtualQuantity", "DynamicMemoryEnabled")
		snap.NICs = append(opt("SELECT InstanceID,Address FROM Msvm_SyntheticEthernetPortSettingData", "InstanceID", "Address"),
			opt("SELECT InstanceID,Address FROM Msvm_EmulatedEthernetPortSettingData", "InstanceID", "Address")...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("hyper-v wmi v1: %w", err)
	}
	return buildHyperVVMsV1(snap), nil
}

func runHyperVControlV1(action, vmID string) (string, error) {
	switch action {
	case "start", "stop", "shutdown", "restart", "save", "pause", "resume":
	default:
		return "", fmt.Errorf("hyperv %s: %w", action, errHyperVV1Unsupported)
	}
	if !validVMGUID(vmID) {
		return "", fmt.Errorf("hyperv %s: invalid VM id %q", action, vmID)
	}
	guid := strings.ToUpper(vmID)
	var opErr error
	err := withWMI(2*time.Minute, func(w *wmiSession) error {
		found := false
		if action == "shutdown" {
			// Graceful: the guest's shutdown integration component.
			err := w.forEachObject(hyperVV1Namespace,
				"SELECT * FROM Msvm_ShutdownComponent WHERE SystemName='"+guid+"'", nil,
				func(obj *ole.IDispatch, _ wmiRow) error {
					found = true
					out, err := execMethod(obj, "InitiateShutdown", map[string]interface{}{"Force": true, "Reason": "Obliance"})
					if err != nil {
						opErr = err
						return nil
					}
					opErr = hyperVV1ReturnError(out.int64v("ReturnValue"))
					return nil
				})
			if err != nil {
				return err
			}
			if !found {
				opErr = fmt.Errorf("guest shutdown service unavailable (VM off or integration services missing)")
			}
			return nil
		}
		state, _ := hyperVV1RequestedState(action)
		err := w.forEachObject(hyperVV1Namespace,
			"SELECT * FROM Msvm_ComputerSystem WHERE Name='"+guid+"'", nil,
			func(obj *ole.IDispatch, _ wmiRow) error {
				found = true
				out, err := execMethod(obj, "RequestStateChange", map[string]interface{}{"RequestedState": state}, "Job")
				if err != nil {
					opErr = err
					return nil
				}
				opErr = hyperVV1ReturnError(out.int64v("ReturnValue"))
				return nil
			})
		if err != nil {
			return err
		}
		if !found {
			opErr = fmt.Errorf("vm not found")
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("hyperv %s: %w", action, err)
	}
	if opErr != nil {
		return "", fmt.Errorf("hyperv %s: %w", action, opErr)
	}
	return fmt.Sprintf("hyperv %s ok", action), nil
}
