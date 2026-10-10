//go:build linux

package main

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// unixMountEscape decodes the octal escapes of /proc/self/mounts ("\040").
func unixMountEscape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x5c && i+3 < len(s) { // a backslash
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unixSystemMount: mount points of the system's own plumbing (containers,
// snaps, runtime folders): never shown.
func unixSystemMount(p string) bool {
	for _, pre := range []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers", "/var/snap"} {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return !strings.HasPrefix(p, "/run/media/")
		}
	}
	return false
}

func unixMounts() []unixMount {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return []unixMount{{path: "/"}}
	}
	defer f.Close()
	var out []unixMount
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		dev, mp, fsType := unixMountEscape(fields[0]), unixMountEscape(fields[1]), fields[2]
		if unixPseudoFs[fsType] || unixSystemMount(mp) {
			continue
		}
		out = append(out, unixMount{path: mp, fsType: fsType, device: dev})
		if len(out) >= 64 {
			break
		}
	}
	// "/" first, then by path (the shortest of a repeated device kept).
	sort.SliceStable(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func unixStatfs(p string) (int64, int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return 0, 0, false
	}
	bs := int64(st.Frsize)
	if bs <= 0 {
		bs = int64(st.Bsize)
	}
	return int64(st.Blocks) * bs, int64(st.Bavail) * bs, true
}
