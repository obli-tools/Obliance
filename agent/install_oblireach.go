package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// handleInstallOblireach is the manual `install_oblireach` command. It goes
// through the same verified pipeline as the automatic ObliReach management
// (oblireach_manager.go): download from the enrolled server only, mandatory
// SHA-256 + size, Authenticode on Windows, refused under privacy mode — but
// without grace period nor backoff.
//   - no payload (the "Install" button): a full reinstall when ObliReach is
//     already there (repair);
//   - payload {mode:"upgrade"} (the "Update Reach" button, 4.5.82+): an
//     update — nothing when already up to date, never uninstall-then-install
//     for a plain upgrade (see InstallNow).
//
// The Oblireach agent uses the same API key as this Obliance agent — the
// server identifies it by the hardware device UUID that both share.
func (d *CommandDispatcher) handleInstallOblireach(cmd AgentCommand) (interface{}, error) {
	mode, _ := cmd.Payload["mode"].(string)
	upgrade := mode == "upgrade"
	if upgrade {
		log.Printf("Command %s: updating Oblireach agent", cmd.ID)
	} else {
		log.Printf("Command %s: installing Oblireach agent", cmd.ID)
	}
	return obliReachMgr.InstallNow(obliReachServer{URL: d.serverURL, APIKey: d.apiKey}, upgrade)
}

// obliReachBinaryName returns the server download filename of the bare
// ObliReach binary for the current platform (Windows installs the MSI, see
// obliReachArtifactName).
func obliReachBinaryName() string {
	switch runtime.GOOS {
	case "windows":
		return "oblireach-agent.exe"
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "oblireach-agent-darwin-arm64"
		}
		return "oblireach-agent-darwin-amd64"
	case "freebsd":
		return "oblireach-agent-freebsd-amd64"
	default: // linux
		return "oblireach-agent-linux-amd64"
	}
}

// obliReachBinaryFileName returns just the local binary filename (no OS suffix).
func obliReachBinaryFileName() string {
	if runtime.GOOS == "windows" {
		return "oblireach-agent.exe"
	}
	return "oblireach-agent"
}

// obliReachInstallDir returns the platform-appropriate installation directory
// of the bare binary (Linux/macOS; on Windows the MSI installs under
// Program Files\OblireachAgent).
func obliReachInstallDir() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "ObliReachAgent")
	case "darwin":
		return "/Library/Application Support/ObliReachAgent"
	default:
		return "/opt/oblireach-agent"
	}
}
