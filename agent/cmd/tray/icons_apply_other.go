//go:build !darwin

package main

import "github.com/getlantern/systray"

// applyIcon sets the colored state icon (Windows ICO, Linux PNG).
func applyIcon(s trayState) {
	systray.SetIcon(coloredIcon(s))
}
