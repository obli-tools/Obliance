//go:build windows
// +build windows

package main

// legacyInventoryScript is the PowerShell 3+ inventory script the agent used
// before the native WMI collection (inventory_windows.go). Kept ONLY as a
// test oracle: TestNativeInventoryMatchesLegacyScript runs both on the test
// machine and compares the resulting InventoryData.
const legacyInventoryScript = `$ErrorActionPreference='SilentlyContinue'
# CPU
$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
# Memory
$mem = Get-WmiObject Win32_PhysicalMemory
$os  = Get-WmiObject Win32_OperatingSystem
# Disks
$disks = Get-WmiObject Win32_DiskDrive
# Network
$nics  = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
# GPU
$gpus  = Get-WmiObject Win32_VideoController
# Motherboard
$mb    = Get-WmiObject Win32_BaseBoard | Select-Object -First 1
# BIOS
$bios  = Get-WmiObject Win32_BIOS | Select-Object -First 1
# Printers
$printers = Get-WmiObject Win32_Printer
# COM/LPT ports (Ports device class — catches real UART, USB-serial adapters, etc.)
$ports = Get-WmiObject Win32_PnPEntity -Filter "PNPClass='Ports'"

$result = @{
  cpu = @{
    model   = $cpu.Name.Trim()
    cores   = [int]$cpu.NumberOfCores
    threads = [int]$cpu.NumberOfLogicalProcessors
    speed   = [int]$cpu.MaxClockSpeed
    arch    = $cpu.AddressWidth
  }
  memTotalMB = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
  memSlots = @($mem | ForEach-Object {
    @{
      slot         = $_.DeviceLocator
      sizeMb       = [math]::Round($_.Capacity / 1MB, 0)
      type         = switch([int]$_.MemoryType){ 20{'DDR'} 21{'DDR2'} 24{'DDR3'} 26{'DDR4'} 34{'DDR5'} default{'Unknown'} }
      speedMhz     = [int]$_.Speed
      manufacturer = $_.Manufacturer.Trim()
    }
  })
  disks = @($disks | ForEach-Object {
    @{
      model      = $_.Model.Trim()
      serial     = $_.SerialNumber.Trim()
      sizeBytes  = [long]$_.Size
      mediaType  = $_.MediaType
      iface      = $_.InterfaceType
    }
  })
  nics = @($nics | ForEach-Object {
    @{
      name    = $_.Description.Trim()
      mac     = $_.MACAddress
      addrs   = @($_.IPAddress)
    }
  })
  gpus = @($gpus | Where-Object {$_.PNPDeviceID -match '^PCI'} | ForEach-Object {
    @{
      model      = $_.Caption.Trim()
      vramBytes  = [long]$_.AdapterRAM
      driverVer  = $_.DriverVersion
    }
  })
  mb = @{
    manufacturer = $mb.Manufacturer.Trim()
    product      = $mb.Product.Trim()
    version      = $mb.Version.Trim()
    serial       = $mb.SerialNumber.Trim()
  }
  bios = @{
    vendor  = $bios.Manufacturer.Trim()
    version = $bios.SMBIOSBIOSVersion.Trim()
    date    = $bios.ReleaseDate
  }
  printers = @($printers | ForEach-Object {
    @{
      name      = $_.Name
      driver    = $_.DriverName
      port      = $_.PortName
      isDefault = [bool]$_.Default
      isNetwork = [bool]$_.Network
      isShared  = [bool]$_.Shared
      status    = switch([int]$_.PrinterStatus){ 1{'Other'} 2{'Unknown'} 3{'Idle'} 4{'Printing'} 5{'Warmup'} 6{'Stopped Printing'} 7{'Offline'} default{'Unknown'} }
    }
  })
  comPorts = @($ports | ForEach-Object {
    $com = if ($_.Caption -match '\((COM\d+)\)') { $matches[1] } else { $null }
    @{
      port        = $com
      description = $_.Caption
      deviceId    = $_.PNPDeviceID
    }
  } | Where-Object { $_.port })
}

# OS details
$osEdition = $os.Caption.Trim()
$osBuild = $os.BuildNumber
$osVer = $os.Version
# DisplayVersion from registry (25H2 etc.)
$dispVer = try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion } catch { '' }
# Windows product key (partial — last 5 via SoftwareLicensingProduct)
$winKey = try { (Get-WmiObject -Query "SELECT OA3xOriginalProductKey FROM SoftwareLicensingService" -ErrorAction Stop).OA3xOriginalProductKey } catch { '' }
if (-not $winKey) { $winKey = try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -ErrorAction Stop).BackupProductKeyDefault } catch { '' } }
# Office version + key
$officeVer = ''
$officeKey = ''
$offPaths = @('HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration', 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstalledPackages')
foreach ($p in $offPaths) {
  if (Test-Path $p) {
    $props = Get-ItemProperty $p -ErrorAction SilentlyContinue
    if ($props.ProductReleaseIds) { $officeVer = $props.ProductReleaseIds; break }
    if ($props.ClientVersionToReport) { $officeVer = "Office " + $props.ClientVersionToReport; break }
  }
}
# Office key last 5 from OSPP
$officeKey = try {
  $ospp = Get-WmiObject -Query "SELECT PartialProductKey,Name FROM SoftwareLicensingProduct WHERE ApplicationId='0ff1ce15-a989-479d-af46-f275c6370663' AND PartialProductKey IS NOT NULL" -ErrorAction Stop | Select-Object -First 1
  if ($ospp) { $ospp.PartialProductKey } else { '' }
} catch { '' }
if ($officeVer -eq '' -and $ospp.Name) { $officeVer = $ospp.Name }

$result['osDetails'] = @{
  edition        = $osEdition
  displayVersion = $dispVer
  buildNumber    = $osVer
  windowsKey     = $winKey
  officeVersion  = $officeVer
  officeKey      = $officeKey
}

# Battery
$bat = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
if ($bat) {
  $design = try { (Get-WmiObject BatteryStaticData -Namespace ROOT\WMI -ErrorAction Stop).DesignedCapacity } catch { 0 }
  $full   = try { (Get-WmiObject BatteryFullChargedCapacity -Namespace ROOT\WMI -ErrorAction Stop).FullChargedCapacity } catch { 0 }
  $cycle  = try { (Get-WmiObject BatteryCycleCount -Namespace ROOT\WMI -ErrorAction Stop).CycleCount } catch { 0 }
  $health = if ($design -gt 0) { [math]::Round($full / $design * 100, 1) } else { 0 }
  $result['battery'] = @{
    present        = $true
    designCapacity = [int]$design
    fullCapacity   = [int]$full
    healthPercent  = $health
    cycleCount     = [int]$cycle
    status         = switch([int]$bat.BatteryStatus){ 1{'Discharging'} 2{'AC Power'} 3{'Full'} 4{'Low'} 5{'Critical'} 6{'Charging'} default{'Unknown'} }
  }
}

# TPM
$tpm = $null
if ($PSVersionTable.PSVersion.Major -ge 3) {
  $tpm = try { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1 } catch { $null }
} else {
  # PowerShell 2.0 (Windows 7 / 2008 R2): no Get-CimInstance, same class via WMI.
  $tpm = try { Get-WmiObject -Namespace root\cimv2\Security\MicrosoftTpm -Class Win32_Tpm -ErrorAction Stop | Select-Object -First 1 } catch { $null }
}
if ($tpm) {
  $result['tpm'] = @{
    present          = $true
    manufacturerName = if($tpm.ManufacturerIdTxt){$tpm.ManufacturerIdTxt}else{''}
    version          = if($tpm.PhysicalPresenceVersionInfo){$tpm.PhysicalPresenceVersionInfo}else{''}
    specVersion      = if($tpm.SpecVersion){$tpm.SpecVersion}else{''}
    status           = if($tpm.IsActivated_InitialValue -and $tpm.IsEnabled_InitialValue){'Ready'}elseif($tpm.IsEnabled_InitialValue){'NotReady'}else{'Disabled'}
    activated        = [bool]$tpm.IsActivated_InitialValue
    enabled          = [bool]$tpm.IsEnabled_InitialValue
    owned            = [bool]$tpm.IsOwned_InitialValue
  }
} else {
  $result['tpm'] = @{ present = $false }
}

$result | ConvertTo-Json -Depth 5 -Compress`

// legacySoftwareScript: the former scanWindowsSoftware PowerShell script (test oracle).
const legacySoftwareScript = `$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -ne $null -and $_.DisplayName.Trim() -ne '' } |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation |
  Sort-Object DisplayName -Unique
$apps | ForEach-Object {
  $line = "$($_.DisplayName)|$($_.DisplayVersion)|$($_.Publisher)|$($_.InstallDate)|$($_.InstallLocation)"
  Write-Output $line
}`

// machineIdentityOracleScript: oracle for the raw keys ADDED after the former
// script (bios.serial, system.*), which the script never printed — so the
// script above stays the untouched historical reference. Get-WmiObject +
// plain text (PowerShell 2.0 compatible): one value per line, in this order:
// Win32_BIOS.SerialNumber, Win32_ComputerSystem Manufacturer / Model /
// SystemFamily / PCSystemType, Win32_ComputerSystemProduct.Version.
// SerialNumber is the value `Get-CimInstance Win32_BIOS | Select SerialNumber`
// prints (same WMI property).
const machineIdentityOracleScript = `$ErrorActionPreference='SilentlyContinue'
$b  = Get-WmiObject Win32_BIOS | Select-Object -First 1
$cs = Get-WmiObject Win32_ComputerSystem | Select-Object -First 1
$p  = Get-WmiObject Win32_ComputerSystemProduct | Select-Object -First 1
$v = @("$($b.SerialNumber)", "$($cs.Manufacturer)", "$($cs.Model)", "$($cs.SystemFamily)", "$($cs.PCSystemType)", "$($p.Version)")
$v | ForEach-Object { 'v=' + $_.Trim() }`
