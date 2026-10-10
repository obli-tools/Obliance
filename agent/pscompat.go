package main

// PowerShell-2.0-compatible scripts and their (platform-independent, unit
// tested) output parsers, used on Windows 7 / 8.1 / Server 2008 R2 / 2012 /
// 2012 R2 where PowerShell 3+ features (ConvertTo-Json, Get-CimInstance, the
// Windows 8 cmdlet modules) are missing. The scripts print plain "KEY|..."
// lines instead of JSON so they run unchanged from PowerShell 2.0 to 5.1.

import (
	"strconv"
	"strings"
)

// ── SecurityCenter2 (third-party antivirus / firewall) ────────────────────────

// securityCenterScript prints at most one "AV=<name>" and one "FW=<name>"
// line: the first non-Microsoft antivirus / firewall product registered in
// SecurityCenter2 (client Windows only).
const securityCenterScript = `$ErrorActionPreference='SilentlyContinue'
$av = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } | Select-Object -First 1
if ($av -and $av.displayName) { 'AV=' + $av.displayName }
$fw = Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -notmatch 'Windows' } | Select-Object -First 1
if ($fw -and $fw.displayName) { 'FW=' + $fw.displayName }`

// parseSecurityCenterOutput reads securityCenterScript's output.
func parseSecurityCenterOutput(out string) (avName, fwName string) {
	for _, line := range strings.Split(strings.TrimPrefix(out, utf8BOM), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "AV=") && avName == "":
			avName = strings.TrimSpace(line[3:])
		case strings.HasPrefix(line, "FW=") && fwName == "":
			fwName = strings.TrimSpace(line[3:])
		}
	}
	return avName, fwName
}

// ── BitLocker through WMI (no BitLocker PowerShell module) ────────────────────

// bitLockerNoModuleMarker is printed by the Get-BitLockerVolume script when
// the BitLocker module is absent (Windows 7 / 2008 R2, or a Server without
// the BitLocker feature) so the caller falls back to the WMI script.
const bitLockerNoModuleMarker = "OBLIANCE_NO_BITLOCKER_MODULE"

// bitLockerWMIScript reads Win32_EncryptableVolume (root\CIMV2\Security\
// MicrosoftVolumeEncryption, Windows Vista+) and prints one line per volume:
//
//	BLV|<mount point>|<ConversionStatus>|<ProtectionStatus>|<EncryptionPercentage>|<key1;key2>
//
// -1 = the method failed. Mount point = drive letter ("C:") or, for volumes
// without one, the volume GUID path — what Get-BitLockerVolume shows.
const bitLockerWMIScript = `$ErrorActionPreference='SilentlyContinue'
$vols = Get-WmiObject -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -ErrorAction SilentlyContinue
foreach ($v in @($vols)) {
  if (-not $v) { continue }
  $mp = $v.DriveLetter
  if (-not $mp) { $mp = $v.DeviceID }
  $conv = -1; $pct = 0
  $cs = $v.GetConversionStatus()
  if ($cs -and $cs.ReturnValue -eq 0) { $conv = [int]$cs.ConversionStatus; $pct = [int]$cs.EncryptionPercentage }
  $prot = -1
  $pst = $v.GetProtectionStatus()
  if ($pst -and $pst.ReturnValue -eq 0) { $prot = [int]$pst.ProtectionStatus }
  $keys = @()
  $kp = $v.GetKeyProtectors(3)
  if ($kp -and $kp.ReturnValue -eq 0) {
    foreach ($id in @($kp.VolumeKeyProtectorID)) {
      if (-not $id) { continue }
      $np = $v.GetKeyProtectorNumericalPassword($id)
      if ($np -and $np.ReturnValue -eq 0 -and $np.NumericalPassword) { $keys += [string]$np.NumericalPassword }
    }
  }
  'BLV|' + $mp + '|' + $conv + '|' + $prot + '|' + $pct + '|' + ($keys -join ';')
}`

// bitLockerVolumeStatusName maps Win32_EncryptableVolume ConversionStatus to
// Get-BitLockerVolume's VolumeStatus name.
func bitLockerVolumeStatusName(conv int) string {
	switch conv {
	case 0:
		return "FullyDecrypted"
	case 1:
		return "FullyEncrypted"
	case 2:
		return "EncryptionInProgress"
	case 3:
		return "DecryptionInProgress"
	case 4:
		return "EncryptionPaused"
	case 5:
		return "DecryptionPaused"
	}
	return "Unknown"
}

// bitLockerProtectionStatusName maps ProtectionStatus to Get-BitLockerVolume's
// ProtectionStatus name.
func bitLockerProtectionStatusName(p int) string {
	switch p {
	case 0:
		return "Off"
	case 1:
		return "On"
	}
	return "Unknown"
}

// parseBitLockerWMIOutput turns bitLockerWMIScript's lines into the same
// BitLockerVolume values the Get-BitLockerVolume JSON produced.
func parseBitLockerWMIOutput(out string) []BitLockerVolume {
	var vols []BitLockerVolume
	for _, line := range strings.Split(strings.TrimPrefix(out, utf8BOM), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "BLV|") {
			continue
		}
		f := strings.SplitN(line[4:], "|", 5)
		if len(f) != 5 || strings.TrimSpace(f[0]) == "" {
			continue
		}
		conv, err1 := strconv.Atoi(strings.TrimSpace(f[1]))
		prot, err2 := strconv.Atoi(strings.TrimSpace(f[2]))
		pct, err3 := strconv.Atoi(strings.TrimSpace(f[3]))
		if err1 != nil {
			conv = -1
		}
		if err2 != nil {
			prot = -1
		}
		if err3 != nil || pct < 0 || pct > 100 {
			pct = 0
		}
		keys := []string{}
		for _, k := range strings.Split(f[4], ";") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		vols = append(vols, BitLockerVolume{
			DriveLetter:          strings.TrimSpace(f[0]),
			Status:               bitLockerVolumeStatusName(conv),
			ProtectionStatus:     bitLockerProtectionStatusName(prot),
			EncryptionPercentage: pct,
			RecoveryKeys:         keys,
		})
	}
	return vols
}

// ── Orphaned update-installer scripts (cleanup_windows.go) ────────────────────

// isOrphanedObliScript: a wscript.exe whose command line mentions obliance
// (the former `-match 'obliance'`, case-insensitive).
func isOrphanedObliScript(exeName, cmdline string) bool {
	return strings.EqualFold(exeName, "wscript.exe") &&
		strings.Contains(strings.ToLower(cmdline), "obliance")
}

// ── TLS 1.2 for agent-run PowerShell scripts on PowerShell < 5 ────────────────

// psTLS12Preamble enables TLS 1.2 for .NET web calls (Invoke-WebRequest,
// WebClient, Invoke-RestMethod...) in scripts run by the agent on PowerShell
// < 5 (Windows 7 / 2008 R2 = 2.0, 2012 = 3.0, 8.1 / 2012 R2 = 4.0), where
// [Net.ServicePointManager]::SecurityProtocol defaults to SSL3 / TLS 1.0 and
// most HTTPS sites refuse the connection. 3072 = Tls12 (the enum member is
// unnamed before .NET 4.5, hence the number); -bor keeps what is already
// enabled. try/catch: on .NET 3.5 without the TLS 1.2 update (KB3154518 and
// friends) the value is rejected — the script then runs exactly as before.
// One line, so the script's own line numbers in error messages move by one.
//
// NOT applied on PowerShell 5+ (Windows 10 / 2016+, or WMF 5.1 installed):
// there the default is SystemDefault (0) on .NET 4.7+, and forcing Tls12
// would only remove TLS 1.3.
const psTLS12Preamble = "try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}\n"

// withPSTLS12Preamble prepends psTLS12Preamble to a PowerShell script when
// the engine is known to be older than 5 (psMajor 1..4; 0 = unknown -> no
// change). A script that starts with a param( block or [CmdletBinding()]
// (after comments / blank lines) is left untouched: param() must be the first
// statement of a script, a preamble line would break its parameters.
func withPSTLS12Preamble(content string, psMajor int) string {
	if psMajor <= 0 || psMajor >= 5 {
		return content
	}
	if psScriptStartsWithParamBlock(content) {
		return content
	}
	return psTLS12Preamble + content
}

// psScriptStartsWithParamBlock: first statement is param(...) or an attribute
// such as [CmdletBinding()] — comments (#..., <# ... #>), blank lines and
// #Requires lines skipped.
func psScriptStartsWithParamBlock(content string) bool {
	s := strings.TrimPrefix(content, utf8BOM)
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		switch {
		case strings.HasPrefix(s, "<#"):
			end := strings.Index(s, "#>")
			if end < 0 {
				return false
			}
			s = s[end+2:]
		case strings.HasPrefix(s, "#"):
			nl := strings.IndexByte(s, '\n')
			if nl < 0 {
				return false
			}
			s = s[nl+1:]
		default:
			l := strings.ToLower(s)
			if strings.HasPrefix(l, "[cmdletbinding") || strings.HasPrefix(l, "[outputtype") {
				return true
			}
			if strings.HasPrefix(l, "param") {
				rest := strings.TrimLeft(l[len("param"):], " \t\r\n")
				return strings.HasPrefix(rest, "(")
			}
			return false
		}
	}
}
