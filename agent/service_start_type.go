package main

// set_service_start_type — change the start type of an OS service from the
// Services tab of the web UI (agent 4.5.103+).
//
// Payload: {"name": "<service>", "startType": "auto" | "auto_delayed" |
// "manual" | "disabled"}. The values are those list_services reports
// (ServiceInfo.StartType), so the UI shows and sends the same words.
//
// Windows (SCM, services_windows.go):
//   auto         = SERVICE_AUTO_START, delayed flag cleared
//   auto_delayed = SERVICE_AUTO_START + delayed auto-start flag
//   manual       = SERVICE_DEMAND_START
//   disabled     = SERVICE_DISABLED
// Linux (systemd only; SysV init and other platforms are refused):
//   auto         = `systemctl unmask` + `systemctl enable` (start at boot)
//   manual       = `systemctl unmask` + `systemctl disable` (startable by hand
//                  or as a dependency, not at boot)
//   disabled     = `systemctl disable` + `systemctl mask` (cannot be started
//                  at all, not even by hand or as a dependency — the closest
//                  to a Windows "Disabled" service)
//   auto_delayed = refused (no systemd equivalent)
// The state of the service (running / stopped) is never changed: "Disable
// and stop" in the UI is this command followed by stop_service.
//
// The agent's own services (the Obliance agent, its watchdog, the ObliReach
// agent) are refused: disabling them remotely would cut the device off.

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// Start types accepted by set_service_start_type, and reported by
// list_services (Windows; Linux systemd through systemdStartTypeName).
const (
	svcStartAuto        = "auto"
	svcStartAutoDelayed = "auto_delayed"
	svcStartManual      = "manual"
	svcStartDisabled    = "disabled"
)

// maxServiceNameLen bounds the name (Windows: 256 characters; systemd: 256).
const maxServiceNameLen = 256

// normalizeServiceStartType validates a requested start type for goos.
func normalizeServiceStartType(goos, v string) (string, error) {
	st := strings.ToLower(strings.TrimSpace(v))
	switch st {
	case svcStartAuto, svcStartManual, svcStartDisabled:
		return st, nil
	case svcStartAutoDelayed:
		if goos != "windows" {
			return "", fmt.Errorf("start type %q is only available on Windows", st)
		}
		return st, nil
	case "":
		return "", fmt.Errorf("startType not specified")
	}
	return "", fmt.Errorf("unknown start type %q (expected auto, auto_delayed, manual or disabled)", v)
}

// validateServiceName refuses names that cannot be a service of goos, and
// anything that could be read as an option by systemctl.
func validateServiceName(goos, name string) error {
	if name == "" {
		return fmt.Errorf("name not specified")
	}
	if len(name) > maxServiceNameLen {
		return fmt.Errorf("service name too long")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return fmt.Errorf("invalid character in service name")
		}
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("invalid service name %q", name)
	}
	switch goos {
	case "windows":
		// The SCM forbids both slashes in a service name.
		if strings.ContainsAny(name, `/\`) {
			return fmt.Errorf("invalid service name %q", name)
		}
	default:
		// systemd unit names: ASCII letters, digits and ":-_.\@" only.
		if strings.HasPrefix(name, "-") {
			return fmt.Errorf("invalid service name %q", name)
		}
		for _, r := range name {
			ok := r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(`:-_.\@`, r))
			if !ok {
				return fmt.Errorf("invalid service name %q", name)
			}
		}
	}
	return nil
}

// isProtectedService reports whether name is one of the agent's own services,
// whose start type must never be changed remotely.
func isProtectedService(goos, name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch goos {
	case "windows":
		// OblianceAgent (this agent, installer/product.wxs) and the ObliReach
		// agent (oblireach_manager_windows.go). The watchdog is a scheduled
		// task on Windows, not a service.
		switch n {
		case "obliancewatchdog", "oblianceagent", "oblireachagent":
			return true
		}
	default:
		// systemd units of the agent (cmd/wizard-linux), its watchdog
		// (watchdog_unix.go) and ObliReach.
		n = strings.TrimSuffix(n, ".service")
		switch n {
		case "obliance-agent", "obliance-watchdog", "oblireach-agent":
			return true
		}
		if strings.HasSuffix(n, ".timer") && strings.TrimSuffix(n, ".timer") == "obliance-watchdog" {
			return true
		}
	}
	return false
}

// systemdStartTypeName maps systemctl's UnitFileState to the list_services
// start type: enabled* = auto, disabled = manual, masked* = disabled; the
// other states (static, indirect, generated, transient, alias...) are shown
// as is.
func systemdStartTypeName(unitFileState string) string {
	s := strings.ToLower(strings.TrimSpace(unitFileState))
	switch {
	case s == "":
		return ""
	case strings.HasPrefix(s, "enabled"):
		return svcStartAuto
	case s == "disabled":
		return svcStartManual
	case strings.HasPrefix(s, "masked"):
		return svcStartDisabled
	}
	return s
}

func (d *CommandDispatcher) handleSetServiceStartType(cmd AgentCommand) (interface{}, error) {
	name := payloadString(cmd.Payload, "name")
	if err := validateServiceName(runtime.GOOS, name); err != nil {
		return nil, fmt.Errorf("set_service_start_type: %w", err)
	}
	startType, err := normalizeServiceStartType(runtime.GOOS, payloadString(cmd.Payload, "startType"))
	if err != nil {
		return nil, fmt.Errorf("set_service_start_type: %w", err)
	}
	if isProtectedService(runtime.GOOS, name) {
		return nil, fmt.Errorf("set_service_start_type: '%s' is an Obliance agent service: its start type cannot be changed remotely", name)
	}

	switch runtime.GOOS {
	case "windows":
		newType, status, err := setServiceStartTypeNative(name, startType)
		if err != nil {
			return nil, fmt.Errorf("set_service_start_type: %w", err)
		}
		return map[string]string{"name": name, "startType": newType, "status": status}, nil

	case "linux":
		if !linuxHasSystemd() {
			return nil, fmt.Errorf("set_service_start_type: only supported with systemd on Linux")
		}
		newType, err := setSystemdStartType(name, startType)
		if err != nil {
			return nil, fmt.Errorf("set_service_start_type: %w", err)
		}
		return map[string]string{"name": name, "startType": newType}, nil

	default:
		return nil, fmt.Errorf("set_service_start_type: changing a service start type is not supported on %s", runtime.GOOS)
	}
}

// systemdStep is one systemctl verb; an optional step may fail (e.g. disable
// on a unit that is already masked).
type systemdStep struct {
	verb     string
	optional bool
}

// systemdSteps is the systemctl verbs that give a unit the start type.
func systemdSteps(startType string) []systemdStep {
	switch startType {
	case svcStartAuto:
		return []systemdStep{{"unmask", false}, {"enable", false}}
	case svcStartManual:
		return []systemdStep{{"unmask", false}, {"disable", false}}
	case svcStartDisabled:
		return []systemdStep{{"disable", true}, {"mask", false}}
	}
	return nil
}

// systemdReached reports whether the UnitFileState read back gives the
// requested start type. "manual" accepts every state that is neither enabled
// nor masked (static, indirect...: units started on demand only).
func systemdReached(startType, unitFileState string) bool {
	got := systemdStartTypeName(unitFileState)
	switch startType {
	case svcStartAuto, svcStartDisabled:
		return got == startType
	case svcStartManual:
		return got != "" && got != svcStartAuto && got != svcStartDisabled
	}
	return false
}

func setSystemdStartType(name, startType string) (string, error) {
	steps := systemdSteps(startType)
	if steps == nil {
		return "", fmt.Errorf("start type %q is not available with systemd", startType)
	}
	// The unit must exist (mask would happily create a /dev/null link for any name).
	if _, err := systemctlShowUnitFileState(name); err != nil {
		return "", err
	}
	for _, step := range steps {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, err := newCmdContext(ctx, "systemctl", step.verb, "--", name).CombinedOutput()
		cancel()
		if err != nil && !step.optional {
			return "", fmt.Errorf("systemctl %s %s failed: %s", step.verb, name, strings.TrimSpace(string(out)))
		}
	}
	state, err := systemctlShowUnitFileState(name)
	if err != nil {
		return "", err
	}
	if !systemdReached(startType, state) {
		hint := ""
		if startType == svcStartAuto {
			hint = " (a unit without an [Install] section cannot be enabled)"
		}
		return "", fmt.Errorf("unit %s is '%s' after the change, not %s%s", name, state, startType, hint)
	}
	return systemdStartTypeName(state), nil
}

// systemctlShowUnitFileState returns the UnitFileState of an existing unit.
func systemctlShowUnitFileState(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := newCmdContext(ctx, "systemctl", "show", "--property=LoadState,UnitFileState", "--", name).Output()
	if err != nil {
		return "", fmt.Errorf("systemctl show %s failed: %w", name, err)
	}
	var load, state string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "LoadState="); ok {
			load = v
		} else if v, ok := strings.CutPrefix(line, "UnitFileState="); ok {
			state = v
		}
	}
	if load == "not-found" {
		return "", fmt.Errorf("unit %s not found", name)
	}
	return state, nil
}
