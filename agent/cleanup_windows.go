//go:build windows

package main

import (
	"log"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

// cleanupOrphanedProcesses kills stuck processes that previous agent runs may
// have left behind — notably wscript.exe hosting COM-based Windows Update
// installers that block waiting for user interaction.
//
// Native (no PowerShell, no wmic → no EDR/SIGMA "process listing" detections,
// and works on PowerShell 2.0 systems where Get-CimInstance does not exist):
// Toolhelp32 snapshot to find wscript.exe, then the command line read from the
// process PEB (gopsutil, Windows 7+, WOW64-aware) for the obliance match.
func cleanupOrphanedProcesses() {
	for _, pid := range findOrphanedObliScripts() {
		if err := terminatePID(pid); err != nil {
			log.Printf("Orphaned wscript.exe (PID %d): kill failed: %v", pid, err)
			continue
		}
		log.Printf("Killed orphaned wscript.exe (PID %d)", pid)
	}
}

func findOrphanedObliScripts() []uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if windows.Process32First(snap, &entry) != nil {
		return nil
	}
	self := uint32(windows.GetCurrentProcessId())
	var pids []uint32
	for {
		pid := entry.ProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])
		// Cheap name filter first: the command line is only read for
		// wscript.exe processes.
		if pid != 0 && pid != self && isOrphanedObliScript(name, "obliance") {
			if p, perr := process.NewProcess(int32(pid)); perr == nil {
				if cmdline, cerr := p.Cmdline(); cerr == nil && isOrphanedObliScript(name, cmdline) {
					pids = append(pids, pid)
				}
			}
		}
		if windows.Process32Next(snap, &entry) != nil {
			break
		}
	}
	return pids
}

// terminatePID = Stop-Process -Force, without spawning taskkill.
func terminatePID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
