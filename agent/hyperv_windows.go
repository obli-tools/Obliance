//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync"
	"time"
)

// ── PowerShell with a deadline ───────────────────────────────────────────────
//
// Every Hyper-V call used to run without any limit: a wedged vmms (or a
// PowerShell stuck on a module load) kept the command running for ever and
// its task stayed "Sent" / "Running". Each call now has a deadline; past it
// the PowerShell process (and its children, through a job object) is killed
// and the command fails with an explicit "timed out" error.

const (
	hyperVDetectTimeout = 45 * time.Second
	hyperVEnumTimeout   = 2 * time.Minute
	hyperVThumbTimeout  = 30 * time.Second
	hyperVStateTimeout  = 30 * time.Second
)

// hyperVControlTimeout: creating a VM (VHDX allocation) or deleting one can
// take a while; power verbs return quickly.
func hyperVControlTimeout(action string) time.Duration {
	switch action {
	case "create", "delete", "checkpoint_apply", "checkpoint_delete", "edit":
		return 15 * time.Minute
	}
	return 5 * time.Minute
}

// psOutputTimeout runs a PowerShell script, killed after `timeout`.
// combined: stdout+stderr as output (error text in it); otherwise stdout
// only, and a failure's error carries the stderr text.
func psOutputTimeout(timeout time.Duration, combined bool, script string) ([]byte, error) {
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	if combined {
		cmd.Stderr = &stdout
	} else {
		cmd.Stderr = &stderr
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := runCmdContextWithJobObject(ctx, cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.Bytes(), fmt.Errorf("PowerShell did not answer within %s (Hyper-V management service busy or hung) — stopped", timeout)
	}
	if err != nil && !combined {
		if reason := strings.TrimSpace(stderr.String()); reason != "" {
			return stdout.Bytes(), fmt.Errorf("%s", truncateStr(reason, 2000))
		}
	}
	return stdout.Bytes(), err
}

// ── Detection (asymmetric timed cache) ───────────────────────────────────────

var (
	hyperVDetectMu sync.Mutex
	hyperVHostType string
	hyperVProbedAt time.Time
	hyperVProbed   bool
)

// hyperVNegativeTTL bounds how stale a NEGATIVE detection can be (see
// detectBackupHost in veeam_windows.go for the rationale). The Hyper-V role
// install reboots, so this bug rarely bites here, but we keep the behaviour
// symmetric so a role added to a never-rebooted host is still picked up.
const hyperVNegativeTTL = 10 * time.Minute

// detectVirtualizationHost returns "hyperv" when the Hyper-V role is present
// and the management service is installed, else "". Positive result is sticky
// for process life; negatives are re-probed every hyperVNegativeTTL.
func detectVirtualizationHost() string {
	hyperVDetectMu.Lock()
	defer hyperVDetectMu.Unlock()

	if hyperVHostType == "hyperv" {
		return hyperVHostType
	}
	if hyperVProbed && time.Since(hyperVProbedAt) < hyperVNegativeTTL {
		return hyperVHostType
	}
	hyperVProbed = true
	hyperVProbedAt = time.Now()

	// vmms = Hyper-V Virtual Machine Management service. Present only when the
	// role is installed. We don't require it to be Running (a host with the
	// role but the service stopped is still a Hyper-V host).
	out, err := psOutputTimeout(hyperVDetectTimeout, false,
		"if (Get-Service vmms -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }")
	if err == nil && strings.TrimSpace(string(out)) == "yes" {
		hyperVHostType = "hyperv"
	}
	return hyperVHostType
}

// ── Enumeration ──────────────────────────────────────────────────────────────

// psCheckpoint mirrors the checkpoint sub-object emitted by the enum script.
type psCheckpoint struct {
	Name       string `json:"name"`
	CreatedAt  string `json:"createdAt"`
	ParentName string `json:"parentName"`
}

// psVM mirrors the ConvertTo-Json shape emitted by enumerateHyperVVMs's script.
type psVM struct {
	VMId              string         `json:"vmId"`
	Name              string         `json:"name"`
	RawState          string         `json:"rawState"`
	CPUCount          int            `json:"cpuCount"`
	MemoryBytes       int64          `json:"memoryBytes"`
	UptimeSeconds     int64          `json:"uptimeSeconds"`
	CheckpointCount   int            `json:"checkpointCount"`
	Checkpoints       []psCheckpoint `json:"checkpoints"`
	IPAddresses       interface{}    `json:"ipAddresses"`  // string | []string | null
	MACAddresses      interface{}    `json:"macAddresses"` // string | []string | null
	Generation        int            `json:"generation"`
	Notes             string         `json:"notes"`
	CPUUsagePercent   int            `json:"cpuUsagePercent"`
	MemoryDemandBytes int64          `json:"memoryDemandBytes"`
	DynamicMemory     bool           `json:"dynamicMemory"`
	Heartbeat         string         `json:"heartbeat"`
	IntegrationSvcVer string         `json:"integrationSvcVer"`
	Version           string         `json:"version"`
	StatusText        string         `json:"statusText"`
	GuestOS           string         `json:"guestOs"`
	AutomaticStart    string         `json:"automaticStart"`
	AutomaticStop     string         `json:"automaticStop"`
}

const enumScript = `
$ErrorActionPreference = 'SilentlyContinue'
# Server 2012 (Hyper-V module v1) names checkpoints "snapshots": Get-VMSnapshot
# (same VMSnapshot objects); Get-VMCheckpoint exists from 2012 R2 / Windows 10.
$getCp = if (Get-Command Get-VMCheckpoint -ErrorAction SilentlyContinue) { 'Get-VMCheckpoint' } else { 'Get-VMSnapshot' }
# Guest OS from the Hyper-V KVP intrinsic items the guest's integration
# services publish (OSName, OSVersion, OSPlatformId): ONE CIM query for all
# VMs, keyed by VM GUID (Msvm_KvpExchangeComponent.SystemName =
# Msvm_ComputerSystem.Name = VMId). Each item is an embedded-instance XML
# string (Msvm_KvpExchangeDataItem: PROPERTY Name / Data). Nothing for a VM
# that is off, or without the Key-Value Pair Exchange integration service.
# Windows guests: OSName ("Windows Server 2022 Datacenter"), OSPlatformId 2.
# Linux guests (hv_kvp_daemon): OSName = os-release NAME ("Ubuntu"), so
# OSVersion ("22.04.4 LTS (Jammy Jellyfish)") is appended.
$kvpOs = @{}
try {
  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $kvps = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_KvpExchangeComponent -ErrorAction Stop)
  } else {
    $kvps = @(Get-WmiObject -Namespace 'root\virtualization\v2' -Class Msvm_KvpExchangeComponent -ErrorAction Stop)
  }
  foreach ($k in $kvps) {
    $items = @{}
    foreach ($x in @($k.GuestIntrinsicExchangeItems)) {
      if (-not $x) { continue }
      try {
        $props = @(([xml]$x).INSTANCE.PROPERTY)
        $n = "$(($props | Where-Object { $_.NAME -eq 'Name' } | Select-Object -First 1).VALUE)"
        $d = "$(($props | Where-Object { $_.NAME -eq 'Data' } | Select-Object -First 1).VALUE)"
        if ($n) { $items[$n] = $d.Trim() }
      } catch {}
    }
    $os = "$($items['OSName'])"
    if ($os) {
      $ver = "$($items['OSVersion'])"
      $isWin = ("$($items['OSPlatformId'])" -eq '2') -or ($os -like '*Windows*')
      if (-not $isWin -and $ver -and $os.IndexOf($ver) -lt 0) { $os = "$os $ver" }
      $kvpOs["$($k.SystemName)".ToUpperInvariant()] = $os
    }
  }
} catch {}
$vms = Get-VM | ForEach-Object {
  $vm = $_
  # One Get-VMNetworkAdapter call feeds both IPs and MACs. IPs need integration
  # services in the guest (often empty); MACs are known by the hypervisor itself
  # and are therefore available for every VM.
  $nics = @(); try { $nics = @($vm | Get-VMNetworkAdapter) } catch {}
  $ips = @(); try { $ips = @($nics.IPAddresses) } catch {}
  $macs = @(); try { $macs = @($nics.MacAddress) } catch {}
  $cps = @()
  try {
    $cps = @(& $getCp -VMName $vm.Name | ForEach-Object {
      [pscustomobject]@{
        name       = $_.Name
        createdAt  = if ($_.CreationTime) { $_.CreationTime.ToUniversalTime().ToString('o') } else { '' }
        parentName = "$($_.ParentSnapshotName)"
      }
    })
  } catch {}
  $guestOs = ''
  try { $guestOs = "$($kvpOs["$($vm.VMId.Guid)".ToUpperInvariant()])" } catch {}
  $isVer = ''
  try { $isVer = "$((Get-VMIntegrationService -VMName $vm.Name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue).PrimaryStatusDescription)" } catch {}
  [pscustomobject]@{
    vmId              = $vm.VMId.Guid
    name              = $vm.Name
    rawState          = "$($vm.State)"
    cpuCount          = [int]$vm.ProcessorCount
    memoryBytes       = [int64]$vm.MemoryAssigned
    uptimeSeconds     = [int64]$vm.Uptime.TotalSeconds
    checkpointCount   = [int]$cps.Count
    checkpoints       = $cps
    ipAddresses       = $ips
    macAddresses      = $macs
    # No Generation property on Server 2012: every VM there is generation 1.
    generation        = if ($vm.Generation) { [int]$vm.Generation } else { 1 }
    notes             = "$($vm.Notes)"
    cpuUsagePercent   = [int]$vm.CPUUsage
    memoryDemandBytes = [int64]$vm.MemoryDemand
    dynamicMemory     = [bool]$vm.DynamicMemoryEnabled
    heartbeat         = "$($vm.Heartbeat)"
    integrationSvcVer = "$($vm.IntegrationServicesVersion)"
    version           = "$($vm.Version)"
    statusText        = "$($vm.Status)"
    guestOs           = $guestOs
    automaticStart    = "$($vm.AutomaticStartAction)"
    automaticStop     = "$($vm.AutomaticStopAction)"
  }
}
# Force an array even for 0/1 VMs so ConvertTo-Json yields [] / [ {} ].
ConvertTo-Json -InputObject @($vms) -Compress -Depth 5
`

// psStringSlice flattens a property that ConvertTo-Json may emit as a bare
// string (single element), an array (n elements) or null (absent). Shared by
// ipAddresses and macAddresses, which both hit this PowerShell quirk.
func psStringSlice(v interface{}) []string {
	out := []string{}
	switch t := v.(type) {
	case string:
		if t != "" {
			out = append(out, t)
		}
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func enumerateHyperVVMs() ([]HyperVVM, error) {
	if hyperVUsesWMIv1() {
		// Server 2008 R2: no Hyper-V module, PowerShell 2.0 (no ConvertTo-Json).
		return enumerateHyperVVMsV1()
	}
	out, err := psOutputTimeout(hyperVEnumTimeout, false, enumScript)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return []HyperVVM{}, nil
	}
	var raw []psVM
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, fmt.Errorf("parse VM json: %w", err)
	}
	vms := make([]HyperVVM, 0, len(raw))
	for _, r := range raw {
		ips := psStringSlice(r.IPAddresses)
		macs := normaliseMACs(psStringSlice(r.MACAddresses))
		cps := make([]HyperVCheckpoint, 0, len(r.Checkpoints))
		for _, c := range r.Checkpoints {
			cps = append(cps, HyperVCheckpoint{Name: c.Name, CreatedAt: c.CreatedAt, ParentName: c.ParentName})
		}
		vms = append(vms, HyperVVM{
			VMId:              r.VMId,
			Name:              r.Name,
			State:             normaliseVMState(r.RawState),
			RawState:          r.RawState,
			CPUCount:          r.CPUCount,
			MemoryBytes:       r.MemoryBytes,
			UptimeSeconds:     r.UptimeSeconds,
			CheckpointCount:   r.CheckpointCount,
			Checkpoints:       cps,
			IPAddresses:       ips,
			MACAddresses:      macs,
			Generation:        r.Generation,
			Notes:             r.Notes,
			CPUUsagePercent:   r.CPUUsagePercent,
			MemoryDemandBytes: r.MemoryDemandBytes,
			DynamicMemory:     r.DynamicMemory,
			Heartbeat:         r.Heartbeat,
			IntegrationSvcVer: r.IntegrationSvcVer,
			Version:           r.Version,
			StatusText:        r.StatusText,
			GuestOS:           r.GuestOS,
			AutomaticStart:    r.AutomaticStart,
			AutomaticStop:     r.AutomaticStop,
		})
	}
	return vms, nil
}

// ── Control ──────────────────────────────────────────────────────────────────

// runHyperVControl performs a control action on a VM addressed by its VMId
// GUID. Returns a short human-readable result message or an error. params
// carries action-specific fields (checkpoint name, edit values, create spec).
func runHyperVControl(action, vmID string, params map[string]interface{}) (string, error) {
	if hyperVUsesWMIv1() {
		return runHyperVControlV1(action, vmID)
	}
	// Resolve the VM by stable Id for everything except create.
	vmRef := fmt.Sprintf("(Get-VM -Id '%s')", psEscape(vmID))

	var script string
	switch action {
	case "start":
		script = fmt.Sprintf("Start-VM -VM %s", vmRef)
	case "stop": // hard power off
		script = fmt.Sprintf("Stop-VM -VM %s -TurnOff -Force", vmRef)
	case "shutdown": // graceful via integration services
		script = fmt.Sprintf("Stop-VM -VM %s -Force", vmRef)
	case "restart":
		script = fmt.Sprintf("Restart-VM -VM %s -Force", vmRef)
	case "save":
		script = fmt.Sprintf("Save-VM -VM %s", vmRef)
	case "pause":
		script = fmt.Sprintf("Suspend-VM -VM %s", vmRef)
	case "resume":
		script = fmt.Sprintf("Resume-VM -VM %s", vmRef)
	case "checkpoint_create":
		name := psStr(params, "checkpointName")
		if name != "" {
			script = fmt.Sprintf("Checkpoint-VM -VM %s -SnapshotName '%s'", vmRef, psEscape(name))
		} else {
			script = fmt.Sprintf("Checkpoint-VM -VM %s", vmRef)
		}
	case "checkpoint_apply":
		name := psStr(params, "checkpointName")
		// Server 2012: *-VMSnapshot only (the *-VMCheckpoint names came later).
		script = fmt.Sprintf("$c = if (Get-Command Restore-VMCheckpoint -ErrorAction SilentlyContinue) { 'Restore-VMCheckpoint' } else { 'Restore-VMSnapshot' }; & $c -VMName ((%s).Name) -Name '%s' -Confirm:$false", vmRef, psEscape(name))
	case "checkpoint_delete":
		name := psStr(params, "checkpointName")
		script = fmt.Sprintf("$c = if (Get-Command Remove-VMCheckpoint -ErrorAction SilentlyContinue) { 'Remove-VMCheckpoint' } else { 'Remove-VMSnapshot' }; & $c -VMName ((%s).Name) -Name '%s'", vmRef, psEscape(name))
	case "edit":
		var parts []string
		if cpu := psInt(params, "cpuCount"); cpu > 0 {
			parts = append(parts, fmt.Sprintf("-ProcessorCount %d", cpu))
		}
		if mem := psInt64(params, "memoryStartupBytes"); mem > 0 {
			parts = append(parts, fmt.Sprintf("-MemoryStartupBytes %d", mem))
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("edit: no recognised settings to apply")
		}
		script = fmt.Sprintf("Set-VM -VM %s %s", vmRef, strings.Join(parts, " "))
	case "create":
		name := psStr(params, "name")
		if name == "" {
			return "", fmt.Errorf("create: name is required")
		}
		cpu := psInt(params, "cpuCount")
		mem := psInt64(params, "memoryStartupBytes")
		gen := psInt(params, "generation")
		sw := psStr(params, "switchName")
		vhdBytes := psInt64(params, "vhdSizeBytes")
		if cpu <= 0 {
			cpu = 2
		}
		if mem <= 0 {
			mem = 2147483648 // 2 GiB
		}
		if gen != 1 && gen != 2 {
			gen = 2
		}
		var b strings.Builder
		fmt.Fprintf(&b, "$vmName='%s'; ", psEscape(name))
		fmt.Fprintf(&b, "$vhd=Join-Path ((Get-VMHost).VirtualHardDiskPath) ($vmName + '.vhdx'); ")
		if vhdBytes <= 0 {
			vhdBytes = 64424509440 // 60 GiB
		}
		// -Generation exists from Server 2012 R2; Server 2012 creates generation-1
		// VMs only and rejects the parameter: splat it only when New-VM has it.
		fmt.Fprintf(&b, "$gp=@{}; if ((Get-Command New-VM).Parameters.ContainsKey('Generation')) { $gp['Generation']=%d }; ", gen)
		fmt.Fprintf(&b, "New-VM -Name $vmName -MemoryStartupBytes %d -NewVHDPath $vhd -NewVHDSizeBytes %d @gp", mem, vhdBytes)
		if sw != "" {
			fmt.Fprintf(&b, " -SwitchName '%s'", psEscape(sw))
		}
		fmt.Fprintf(&b, "; Set-VM -Name $vmName -ProcessorCount %d", cpu)
		script = b.String()
	case "delete":
		// Force off first so Remove-VM doesn't refuse on a running guest.
		script = fmt.Sprintf("Stop-VM -VM %s -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -VM %s -Force", vmRef, vmRef)
	default:
		return "", fmt.Errorf("unknown hyperv action %q", action)
	}

	full := "$ErrorActionPreference='Stop'; " + script
	out, err := psOutputTimeout(hyperVControlTimeout(action), true, full)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	return fmt.Sprintf("hyperv %s ok", action), nil
}

// ── Console thumbnail (A layer) ──────────────────────────────────────────────
//
// Grabs the VM framebuffer via Msvm_VirtualSystemManagementService.
// GetVirtualSystemThumbnailImage — the same RGB565 thumbnail Hyper-V Manager
// and VMConnect render as a preview. Works at BIOS / boot / login, no guest
// agent. We ask PowerShell/CIM for the raw RGB565 bytes (base64) + actual
// dimensions, then convert to PNG in Go.

const thumbScriptTmpl = `
$ErrorActionPreference='Stop'
$ns='root\virtualization\v2'
$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='%s'"
if (-not $vm) { throw 'vm not found' }
$vssd = Get-CimAssociatedInstance -InputObject $vm -Namespace $ns -ResultClassName Msvm_VirtualSystemSettingData -Association Msvm_SettingsDefineState | Select-Object -First 1
$svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
$res = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $vssd; WidthPixels = [uint16]%d; HeightPixels = [uint16]%d }
if ($res.ReturnValue -ne 0 -or -not $res.ImageData) { throw "thumbnail unavailable (rv=$($res.ReturnValue)) - VM may be off or have no framebuffer" }
# Emit ONLY the base64 (no prefix). The image is exactly WidthPixels x
# HeightPixels (the method scales the framebuffer), so Go reuses the
# requested dimensions. Outputting just base64 lets Go strip any line
# wrapping PowerShell might introduce on the long string.
[Convert]::ToBase64String($res.ImageData)
`

// captureHyperVThumbnail returns a base64-encoded PNG of the VM console at
// (w x h). Errors carry a human reason (VM off / no framebuffer / host
// refused) so the UI can show why the console is blank.
func captureHyperVThumbnail(vmID string, w, h int) (string, error) {
	if hyperVUsesWMIv1() {
		return "", fmt.Errorf("console preview: %w", errHyperVV1Unsupported)
	}
	script := fmt.Sprintf(thumbScriptTmpl, psEscape(vmID), w, h)
	out, err := psOutputTimeout(hyperVThumbTimeout, false, script)
	if err != nil {
		// stdout stays clean (just the base64). On failure the PowerShell
		// `throw` text (stderr) is in the error, so the UI shows the real
		// reason (VM off / no framebuffer) not just "exit 1".
		return "", err
	}
	// Strip ALL whitespace (incl. any newlines PowerShell may have wrapped
	// the long base64 string with) before decoding.
	b64 := strings.Join(strings.Fields(string(out)), "")
	if b64 == "" {
		return "", fmt.Errorf("empty thumbnail output")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode thumbnail bytes: %w", err)
	}
	pngBytes, err := rgb565ToPNG(raw, w, h)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pngBytes), nil
}

// rgb565ToPNG converts a little-endian RGB565 framebuffer to PNG bytes.
func rgb565ToPNG(data []byte, w, h int) ([]byte, error) {
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid thumbnail dimensions %dx%d", w, h)
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	n := w * h
	for i := 0; i < n; i++ {
		if 2*i+1 >= len(data) {
			break
		}
		px := uint16(data[2*i]) | uint16(data[2*i+1])<<8
		r := uint8((px>>11)&0x1f) << 3
		g := uint8((px>>5)&0x3f) << 2
		b := uint8(px&0x1f) << 3
		img.SetRGBA(i%w, i/w, color.RGBA{R: r, G: g, B: b, A: 255})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── PowerShell helpers ───────────────────────────────────────────────────────

// psEscape doubles single quotes for safe interpolation into a single-quoted
// PowerShell string literal.
func psEscape(s string) string { return strings.ReplaceAll(s, "'", "''") }

func psStr(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func psInt(m map[string]interface{}, k string) int {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func psInt64(m map[string]interface{}, k string) int64 {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}
