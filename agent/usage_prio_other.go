//go:build !windows && !linux

package main

// usageLowPriority: macOS and FreeBSD have no per-thread nice for a Go
// program without cgo: the scan runs at the agent's priority (its workers
// are few and mostly wait on the disk).
func usageLowPriority() {}
