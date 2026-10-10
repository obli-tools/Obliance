//go:build !windows

package main

// files_roots_unix.go — the mounted file systems of the roots listing
// (listRoots "volumes"), each queried in parallel and all of them waited for
// rootInfoWait at most (an NFS / CIFS mount that hangs is left out). The
// list of mounts: files_roots_linux.go / files_roots_bsd.go.

import (
	"sync"
	"time"
)

// rootsVolumeInfo: the Windows drives only.
func rootsVolumeInfo(roots []FileInfo) {}

// A mount whose query has not come back yet is not queried again until it
// does: listings never pile up blocked queries.
var rootInfoBusy sync.Map

type unixMount struct {
	path, fsType, device string
}

// unixPseudoFs: file systems that hold no user data (or only a view of
// another one): never shown.
var unixPseudoFs = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "ramfs": true,
	"cgroup": true, "cgroup2": true, "pstore": true, "bpf": true, "tracefs": true, "debugfs": true,
	"securityfs": true, "configfs": true, "fusectl": true, "mqueue": true, "hugetlbfs": true,
	"autofs": true, "binfmt_misc": true, "overlay": true, "squashfs": true, "nsfs": true,
	"efivarfs": true, "rpc_pipefs": true, "nfsd": true, "selinuxfs": true, "fuse.gvfsd-fuse": true,
	"fuse.portal": true, "fuse.lxcfs": true, "devfs": true, "fdescfs": true, "procfs": true,
	"linprocfs": true, "linsysfs": true, "nullfs": true, "kernfs": true, "ptyfs": true, "none": true,
}

func unixVolumes() []VolumeInfo {
	mounts := unixMounts()
	type res struct {
		v  VolumeInfo
		ok bool
	}
	chans := make([]chan res, len(mounts))
	for i, m := range mounts {
		ch := make(chan res, 1)
		chans[i] = ch
		m := m
		if _, busy := rootInfoBusy.LoadOrStore(m.path, true); busy {
			ch <- res{}
			continue
		}
		go func() {
			defer rootInfoBusy.Delete(m.path)
			total, free, ok := unixStatfs(m.path)
			ch <- res{VolumeInfo{Path: m.path, TotalBytes: total, FreeBytes: free, FsType: m.fsType, Device: m.device}, ok && total > 0}
		}()
	}
	timer := time.NewTimer(rootInfoWait)
	defer timer.Stop()
	expired := false
	var out []VolumeInfo
	seen := map[string]bool{}
	for _, ch := range chans {
		var r res
		if expired {
			select {
			case r = <-ch:
			default:
				continue
			}
		} else {
			select {
			case r = <-ch:
			case <-timer.C:
				expired = true
				continue
			}
		}
		if !r.ok {
			continue
		}
		// One line per file system (a bind mount repeats its device).
		if r.v.Device != "" && seen[r.v.Device] {
			continue
		}
		if r.v.Device != "" {
			seen[r.v.Device] = true
		}
		out = append(out, r.v)
	}
	return out
}
