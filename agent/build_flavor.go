package main

import "runtime"

// buildFlavor selects the Windows build line of this binary. It is injected at
// build time and is "" (= modern) unless the build script says otherwise:
//
//	go build -ldflags "-X main.agentVersion=x.y.z -X main.buildFlavor=nt6" ...
//
// "nt6" = the full-featured agent built with Go 1.20 (go120.mod) for Windows 7
// SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2. Same source code as the modern
// agent; it only exists because a binary built with Go >= 1.21 dies before
// main() on Windows 7 / 2008 R2 (runtime → ProcessPrng in
// bcryptprimitives.dll, no fallback) and Go 1.21+ dropped Windows < 10
// support altogether.
//
// NOTE: this is NOT the reduced "legacy" agent (cmd/legacy, Server 2008 R2,
// 23 commands). The nt6 build reports agentFlavor "modern" so the server keeps
// every feature on; agentBuild tells the two Windows build lines apart.
var buildFlavor = ""

const buildFlavorNT6 = "nt6"

// isNT6Build reports whether this binary is the Go 1.20 build for Windows < 10.
func isNT6Build() bool { return buildFlavor == buildFlavorNT6 }

// agentBuildName is the value reported in the push body as `agentBuild`.
func agentBuildName() string {
	if isNT6Build() {
		return buildFlavorNT6
	}
	return "modern"
}

// agentMSIName is the installer this agent downloads to update itself on
// Windows. The nt6 build must stay on the nt6 line (a modern MSI would install
// a binary that cannot start on Windows 7 / 2008 R2, and the modern MSI
// refuses Windows < 10 anyway); a modern agent running on Windows NT 6.x
// (8.1 / 2012 / 2012 R2 installs made before the nt6 line) moves to it at
// its next update (osNeedsNT6Build), and stays on modern on Windows 10+.
func agentMSIName(goarch string, nt6 bool) string {
	name := "obliance-agent"
	if nt6 {
		name += "-nt6"
	}
	if goarch == "386" {
		name += "-x86"
	}
	return name + ".msi"
}

// currentAgentMSIName is agentMSIName for this binary on this OS.
func currentAgentMSIName() string {
	return agentMSIName(runtime.GOARCH, isNT6Build() || osNeedsNT6Build())
}
