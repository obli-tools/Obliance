//go:build windows

package main

// files_roots_windows.go — the space, label and file system of each drive
// of the roots listing (listRoots), each drive queried in parallel, all of
// them waited for rootInfoWait at most.

import (
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// A drive whose query has not come back yet (a hung network drive) is not
// queried again until it does: listings never pile up blocked queries.
var rootInfoBusy sync.Map

type rootVolume struct {
	ok              bool
	total, free     int64
	label, fs, kind string
}

func rootDriveKind(t uint32) string {
	switch t {
	case windows.DRIVE_FIXED:
		return "fixed"
	case windows.DRIVE_REMOVABLE:
		return "removable"
	case windows.DRIVE_REMOTE:
		return "network"
	case windows.DRIVE_CDROM:
		return "cdrom"
	case windows.DRIVE_RAMDISK:
		return "ramdisk"
	}
	return ""
}

func queryRootVolume(root string) rootVolume {
	var v rootVolume
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return v
	}
	v.kind = rootDriveKind(windows.GetDriveType(p))
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree); err == nil && total > 0 {
		v.ok = true
		v.total = int64(total)
		v.free = int64(avail)
	}
	label := make([]uint16, windows.MAX_PATH+1)
	fsName := make([]uint16, windows.MAX_PATH+1)
	var serial, maxLen, flags uint32
	if err := windows.GetVolumeInformation(p, &label[0], uint32(len(label)), &serial, &maxLen, &flags, &fsName[0], uint32(len(fsName))); err == nil {
		v.label = windows.UTF16ToString(label)
		v.fs = windows.UTF16ToString(fsName)
	}
	return v
}

func rootsVolumeInfo(roots []FileInfo) {
	chans := make([]chan rootVolume, len(roots))
	for i := range roots {
		ch := make(chan rootVolume, 1)
		chans[i] = ch
		root := roots[i].Path
		if _, busy := rootInfoBusy.LoadOrStore(root, true); busy {
			ch <- rootVolume{}
			continue
		}
		go func() {
			defer rootInfoBusy.Delete(root)
			ch <- queryRootVolume(root)
		}()
	}
	timer := time.NewTimer(rootInfoWait)
	defer timer.Stop()
	expired := false
	for i, ch := range chans {
		var v rootVolume
		if expired {
			select {
			case v = <-ch:
			default:
				continue
			}
		} else {
			select {
			case v = <-ch:
			case <-timer.C:
				expired = true
				continue
			}
		}
		roots[i].Label = v.label
		roots[i].FsType = v.fs
		roots[i].DriveType = v.kind
		if v.ok {
			t, f := v.total, v.free
			roots[i].TotalBytes = &t
			roots[i].FreeBytes = &f
		}
	}
}

// unixVolumes: Unix only.
func unixVolumes() []VolumeInfo { return nil }
