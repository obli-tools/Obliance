//go:build windows

package main

// osNeedsNT6Build: Windows 7 SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2
// (NT 6.x) must run the nt6 build. A modern agent already installed on such
// a system (8.1 / 2012 / 2012 R2 could run Go 1.22 binaries) moves to the nt6
// line at its next update: the modern MSI now refuses Windows < 10.
func osNeedsNT6Build() bool {
	major, _, _ := windowsOSVersion()
	return major != 0 && major < 10
}
