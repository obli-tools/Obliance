//go:build darwin || freebsd

package main

import (
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

func unixCString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func unixMounts() []unixMount {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n <= 0 {
		return []unixMount{{path: "/"}}
	}
	buf := make([]unix.Statfs_t, n)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return []unixMount{{path: "/"}}
	}
	var out []unixMount
	for _, st := range buf[:n] {
		mp := unixCString(st.Mntonname[:])
		fsType := unixCString(st.Fstypename[:])
		if unixPseudoFs[fsType] || mp == "" {
			continue
		}
		// macOS: the system's own volumes of the APFS container (the user
		// data is /System/Volumes/Data, shown) are left out.
		if strings.HasPrefix(mp, "/System/Volumes/") && mp != "/System/Volumes/Data" {
			continue
		}
		if strings.HasPrefix(mp, "/private/var/") || strings.HasPrefix(mp, "/dev") {
			continue
		}
		out = append(out, unixMount{path: mp, fsType: fsType, device: unixCString(st.Mntfromname[:])})
		if len(out) >= 64 {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func unixStatfs(p string) (int64, int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return 0, 0, false
	}
	bs := int64(st.Bsize)
	return int64(st.Blocks) * bs, int64(st.Bavail) * bs, true
}
