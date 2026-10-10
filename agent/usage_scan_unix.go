//go:build !windows

package main

// usage_scan_unix.go — the Unix parts of the disk usage analyzer
// (usage_scan.go): links, file system boundary, hard links, allocated sizes.
// The thread priority: usage_prio_linux.go / usage_prio_other.go.

import (
	"io/fs"
	"os"
	"syscall"
)

func usageLongPath(p string) string { return p }

// usageIsLink: symbolic links are never followed nor counted.
func usageIsLink(dir string, e os.DirEntry) bool { return e.Type()&os.ModeSymlink != 0 }

// usageDevice: the file system of an entry (st_dev): a scan stays on its root's.
func usageDevice(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return uint64(st.Dev), true
}

// usageLinkKey: (device, inode) of a file with several hard links (counted once).
func usageLinkKey(info fs.FileInfo) ([2]uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil || uint64(st.Nlink) < 2 {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(st.Dev), uint64(st.Ino)}, true
}

// usageAlloc: the blocks a file holds (st_blocks, 512-byte units).
func usageAlloc(dir, name string, info fs.FileInfo, cluster int64) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil && st.Blocks >= 0 {
		return int64(st.Blocks) * 512
	}
	if info.Size() < 0 {
		return 0
	}
	return info.Size()
}

func usageClusterSize(root string) int64 { return 512 }
