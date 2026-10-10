//go:build windows

package main

// usage_scan_windows.go — the Windows parts of the disk usage analyzer
// (usage_scan.go): background thread priority, links, allocated sizes.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32Usage          = windows.NewLazySystemDLL("kernel32.dll")
	procSetThreadPriorityU    = modKernel32Usage.NewProc("SetThreadPriority")
	procGetCompressedFileSize = modKernel32Usage.NewProc("GetCompressedFileSizeW")
	procGetDiskFreeSpaceU     = modKernel32Usage.NewProc("GetDiskFreeSpaceW")
)

const (
	usageThreadModeBackgroundBegin = 0x00010000
	usageReparseNameSurrogate      = 0x20000000
	usageAttrRecallOnOpen          = 0x00040000
	usageAttrRecallOnDataAccess    = 0x00400000
)

// usageLowPriority: background mode for the calling OS thread (lower I/O and
// memory priority, Vista and later). The caller holds LockOSThread.
func usageLowPriority() {
	if procSetThreadPriorityU.Find() != nil {
		return
	}
	// GetCurrentThread: the pseudo handle (-2), never closed.
	_, _, _ = procSetThreadPriorityU.Call(uintptr(^uintptr(1)), uintptr(usageThreadModeBackgroundBegin))
}

// usageLongPath: the \\?\ form of a long absolute path (os.Open does it by
// itself; the raw Win32 calls here do not).
func usageLongPath(p string) string {
	if len(p) < 248 || strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		return `\\?\` + p
	}
	return p
}

func usageAttrs(info fs.FileInfo) (uint32, bool) {
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok && d != nil {
		return d.FileAttributes, true
	}
	return 0, false
}

// usageIsLink: never walked into. Symbolic links and junctions (mount points
// included), and any folder whose reparse point is a name surrogate (another
// name for something elsewhere). A folder with another reparse point (cloud
// files, a OneDrive folder) is a real folder.
func usageIsLink(dir string, e os.DirEntry) bool {
	t := e.Type()
	if t&os.ModeSymlink != 0 {
		return true
	}
	if !e.IsDir() && t&os.ModeIrregular == 0 {
		return false
	}
	info, err := e.Info()
	if err != nil {
		return false
	}
	if !info.IsDir() && t&os.ModeIrregular != 0 {
		return false // a file with a reparse point (cloud, dedup): counted
	}
	a, ok := usageAttrs(info)
	if !ok || a&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false
	}
	tag, ok := usageReparseTag(filepath.Join(dir, e.Name()))
	if !ok {
		return true // unknown: never walked into
	}
	return tag&usageReparseNameSurrogate != 0
}

// usageReparseTag reads the reparse tag of a path without following it.
func usageReparseTag(p string) (uint32, bool) {
	name, err := windows.UTF16PtrFromString(usageLongPath(p))
	if err != nil {
		return 0, false
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	var ti struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti))); err != nil {
		return 0, false
	}
	return ti.ReparseTag, true
}

// usageDevice: no device check on Windows (links and mount points are never
// walked into, so a scan stays on its volume).
func usageDevice(info fs.FileInfo) (uint64, bool) { return 0, false }

// usageLinkKey: hard links are not detected on Windows (it would cost one
// open per file): a file with several names is counted under each.
func usageLinkKey(info fs.FileInfo) ([2]uint64, bool) { return [2]uint64{}, false }

func usageRoundUp(v, cluster int64) int64 {
	if v <= 0 || cluster <= 1 {
		if v < 0 {
			return 0
		}
		return v
	}
	return (v + cluster - 1) / cluster * cluster
}

// usageAlloc: the space a file takes on the disk (see usage_scan.go).
func usageAlloc(dir, name string, info fs.FileInfo, cluster int64) int64 {
	size := info.Size()
	a, ok := usageAttrs(info)
	if ok {
		if a&(windows.FILE_ATTRIBUTE_OFFLINE|usageAttrRecallOnOpen|usageAttrRecallOnDataAccess) != 0 {
			return 0
		}
		if a&(windows.FILE_ATTRIBUTE_COMPRESSED|windows.FILE_ATTRIBUTE_SPARSE_FILE) != 0 {
			if v, ok := usageCompressedSize(filepath.Join(dir, name)); ok {
				return usageRoundUp(v, cluster)
			}
		}
	}
	return usageRoundUp(size, cluster)
}

func usageCompressedSize(p string) (int64, bool) {
	if procGetCompressedFileSize.Find() != nil {
		return 0, false
	}
	name, err := windows.UTF16PtrFromString(usageLongPath(p))
	if err != nil {
		return 0, false
	}
	var high uint32
	low, _, e := procGetCompressedFileSize.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&high)))
	if uint32(low) == 0xFFFFFFFF && e != nil && e != windows.ERROR_SUCCESS {
		return 0, false
	}
	return int64(high)<<32 | int64(uint32(low)), true
}

// usageClusterSize: the cluster of the volume holding root (4096 when it
// cannot be read).
func usageClusterSize(root string) int64 {
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 4096
	}
	buf := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumePathName(name, &buf[0], uint32(len(buf))); err != nil {
		return 4096
	}
	if procGetDiskFreeSpaceU.Find() != nil {
		return 4096
	}
	var spc, bps, free, total uint32
	r, _, _ := procGetDiskFreeSpaceU.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&spc)), uintptr(unsafe.Pointer(&bps)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)))
	if r == 0 || spc == 0 || bps == 0 {
		return 4096
	}
	return int64(spc) * int64(bps)
}
