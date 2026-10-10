package main

// trayState is the icon state, by priority (highest first):
// airgap (blue) > remote session (red) > service stopped (grey) >
// privacy (orange) > normal (green). Identical on every platform.
type trayState int

const (
	stateNormal trayState = iota
	statePrivacy
	stateDisconnected
	stateRemote
	stateAirgap
)

// computeState applies the icon priority.
func computeState(airgap, remote, running, privacy bool) trayState {
	switch {
	case airgap:
		return stateAirgap
	case remote:
		return stateRemote
	case !running:
		return stateDisconnected
	case privacy:
		return statePrivacy
	default:
		return stateNormal
	}
}

// coloredIcon returns the colored icon bytes of a state (icons_*.go).
func coloredIcon(s trayState) []byte {
	switch s {
	case stateAirgap:
		return iconAirgap
	case stateRemote:
		return iconRemote
	case stateDisconnected:
		return iconDisconnected
	case statePrivacy:
		return iconPrivacy
	default:
		return iconNormal
	}
}

// tooltipFor returns the tooltip of a state.
func tooltipFor(s trayState, protocol string, privacyLocked bool) string {
	switch s {
	case stateAirgap:
		return "Obliance Agent — AIRGAP (network isolated)"
	case stateRemote:
		t := "Obliance Agent — Remote session active"
		if protocol != "" {
			t += " (" + protocol + ")"
		}
		return t
	case stateDisconnected:
		return "Obliance Agent — Disconnected"
	case statePrivacy:
		if privacyLocked {
			return "Obliance Agent — Privacy Mode ON (locked)"
		}
		return "Obliance Agent — Privacy Mode ON"
	default:
		return "Obliance Agent"
	}
}

// statusLineFor returns the (disabled) "Status: ..." menu line.
func statusLineFor(airgap, remote, running bool, protocol string) string {
	switch {
	case airgap:
		return "Status: AIRGAP — Network isolated"
	case remote:
		label := "Status: Remote session"
		if protocol != "" {
			label += " (" + protocol + ")"
		}
		return label
	case running:
		return "Status: Connected"
	default:
		return "Status: Disconnected"
	}
}

// privacyItemFor returns the privacy menu item title and whether it is
// clickable (a locked privacy.json greys it out).
func privacyItemFor(enabled, locked bool) (string, bool) {
	switch {
	case enabled && locked:
		return "Privacy Mode: ON  (locked)", false
	case enabled:
		return "Privacy Mode: ON  (click to disable)", true
	case locked:
		return "Privacy Mode: OFF  (locked)", false
	default:
		return "Privacy Mode: OFF  (click to enable)", true
	}
}
