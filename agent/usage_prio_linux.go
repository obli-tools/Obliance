//go:build linux

package main

import "golang.org/x/sys/unix"

// usageLowPriority: the calling OS thread at nice 19 and in the best-effort
// I/O class at its lowest level (the caller holds LockOSThread; Linux
// applies both per thread). Best effort: failures are ignored.
func usageLowPriority() {
	tid := unix.Gettid()
	_ = unix.Setpriority(unix.PRIO_PROCESS, tid, 19)
	const ioprioWhoProcess = 1
	const ioprioClassBE = 2
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), uintptr(ioprioClassBE<<13|7))
}
