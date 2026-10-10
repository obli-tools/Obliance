package main

import (
	"strings"
	"testing"
)

func TestComputeStatePriority(t *testing.T) {
	cases := []struct {
		airgap, remote, running, privacy bool
		want                             trayState
	}{
		{true, true, false, true, stateAirgap},
		{true, false, true, false, stateAirgap},
		{false, true, false, true, stateRemote},
		{false, true, true, false, stateRemote},
		{false, false, false, true, stateDisconnected},
		{false, false, false, false, stateDisconnected},
		{false, false, true, true, statePrivacy},
		{false, false, true, false, stateNormal},
	}
	for _, c := range cases {
		if got := computeState(c.airgap, c.remote, c.running, c.privacy); got != c.want {
			t.Errorf("computeState(airgap=%v remote=%v running=%v privacy=%v) = %v, want %v",
				c.airgap, c.remote, c.running, c.privacy, got, c.want)
		}
	}
}

func TestPrivacyItemLock(t *testing.T) {
	for _, c := range []struct {
		enabled, locked, clickable bool
		contains                   string
	}{
		{false, false, true, "OFF  (click to enable)"},
		{true, false, true, "ON  (click to disable)"},
		{false, true, false, "OFF  (locked)"},
		{true, true, false, "ON  (locked)"},
	} {
		title, clickable := privacyItemFor(c.enabled, c.locked)
		if clickable != c.clickable || !strings.Contains(title, c.contains) {
			t.Errorf("privacyItemFor(%v,%v) = %q,%v", c.enabled, c.locked, title, clickable)
		}
	}
}

func TestTooltipAndStatus(t *testing.T) {
	if got := tooltipFor(stateRemote, "ssh", false); got != "Obliance Agent — Remote session active (ssh)" {
		t.Errorf("remote tooltip = %q", got)
	}
	if got := tooltipFor(statePrivacy, "", true); !strings.Contains(got, "locked") {
		t.Errorf("locked privacy tooltip = %q", got)
	}
	if got := statusLineFor(false, false, true, ""); got != "Status: Connected" {
		t.Errorf("status = %q", got)
	}
	if got := statusLineFor(true, true, true, ""); !strings.Contains(got, "AIRGAP") {
		t.Errorf("airgap status = %q", got)
	}
	for _, s := range []trayState{stateNormal, statePrivacy, stateDisconnected, stateRemote, stateAirgap} {
		if len(coloredIcon(s)) == 0 {
			t.Errorf("no icon embedded for state %v", s)
		}
	}
}
