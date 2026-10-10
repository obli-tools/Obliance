//go:build windows

package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Windows Firewall profile state, read natively from the registry: the local
// (persistent-store) settings Get-NetFirewallProfile reports by default, on
// every Windows version — Get-NetFirewallProfile (NetSecurity module) only
// exists on Windows 8 / Server 2012+.
//
// Get-NetFirewallProfile's Domain / Private / Public profiles are stored as
// DomainProfile / StandardProfile / PublicProfile.

const firewallPolicyKey = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`

var firewallProfileKeys = []string{"DomainProfile", "StandardProfile", "PublicProfile"}

// firewallValueReader returns EnableFirewall for one profile key:
// (value, present, error). error = the profile key itself is unreadable.
type firewallValueReader func(profile string) (uint32, bool, error)

// countEnabledFirewallProfiles counts the enabled profiles; readable=false
// when no profile key could be read at all. A profile whose EnableFirewall
// value is absent is enabled (Windows' default).
func countEnabledFirewallProfiles(read firewallValueReader) (enabled int, readable bool) {
	for _, p := range firewallProfileKeys {
		v, present, err := read(p)
		if err != nil {
			continue
		}
		readable = true
		if !present || v != 0 {
			enabled++
		}
	}
	return enabled, readable
}

func registryFirewallValue(profile string) (uint32, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, firewallPolicyKey+`\`+profile, registry.QUERY_VALUE)
	if err != nil {
		return 0, false, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("EnableFirewall")
	if err == registry.ErrNotExist {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return uint32(v), true, nil
}

// windowsFirewallStatus returns "profiles_enabled:N" (the format the former
// Get-NetFirewallProfile count produced) or "unknown".
func windowsFirewallStatus() string {
	if n, ok := countEnabledFirewallProfiles(registryFirewallValue); ok {
		return "profiles_enabled:" + strconv.Itoa(n)
	}
	// Registry unreadable (should not happen as SYSTEM): NetSecurity cmdlet
	// where it exists.
	if psAtLeast(3) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := runPSContext(ctx,
			`(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true} | Measure-Object).Count`)
		if s := strings.TrimSpace(string(out)); err == nil && s != "" {
			if _, aerr := strconv.Atoi(s); aerr == nil {
				return "profiles_enabled:" + s
			}
		}
	}
	return "unknown"
}
