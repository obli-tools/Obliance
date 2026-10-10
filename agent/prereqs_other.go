//go:build !windows

package main

// nt6PrereqsForPush: Windows NT 6.x only.
func nt6PrereqsForPush() *NT6Prereqs { return nil }
