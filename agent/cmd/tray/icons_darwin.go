//go:build darwin

package main

import (
	_ "embed"

	"github.com/getlantern/systray"
)

// macOS menu-bar icons. The normal and disconnected states use template
// images (black + alpha, generated from icon_normal.png): macOS tints them
// for light/dark menu bars and the selected state, like native status items.
// Disconnected is the same glyph at 40 % opacity (the macOS "inactive"
// look). The alert states keep their color so they stand out: privacy
// orange, remote session red, airgap blue.

//go:embed icon_template.png
var iconTemplateNormal []byte

//go:embed icon_template_disconnected.png
var iconTemplateDisconnected []byte

func applyIcon(s trayState) {
	switch s {
	case stateNormal:
		systray.SetTemplateIcon(iconTemplateNormal, iconNormal)
	case stateDisconnected:
		systray.SetTemplateIcon(iconTemplateDisconnected, iconDisconnected)
	default:
		systray.SetIcon(coloredIcon(s))
	}
}
