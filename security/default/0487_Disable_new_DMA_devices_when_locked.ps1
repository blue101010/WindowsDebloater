<#
.SYNOPSIS
Blocks new DMA-capable devices while the computer is locked (BitLocker DMA countermeasure).

.DESCRIPTION
CIS 18.9.11.5 (BL), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Disable new DMA devices when this computer is locked = Enabled (DisableExternalDMAUnderLock = 1)

.NOTES
Windows 11 only; run as Administrator.
Microsoft states that this BitLocker countermeasure is not compatible with Kernel DMA
Protection and should be disabled when Kernel DMA Protection is supported. The script
therefore makes no change when Kernel DMA Protection is enabled or its state is unknown.
Thunderbolt/USB4 devices plugged in while the session is locked will not work until unlock.
https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
#>

$scriptName = "0487_Disable_new_DMA_devices_when_locked"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

function Get-KernelDmaProtectionState {
  if (-not ('WindowsDebloater.KernelDmaProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace WindowsDebloater {
  public static class KernelDmaProbe {
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int infoClass, ref byte info, int length, out int returnLength);
  }
}
'@
  }
  $enabled = [byte]0
  $returned = 0
  # 202 = SystemDmaGuardPolicyInformation
  $status = [WindowsDebloater.KernelDmaProbe]::NtQuerySystemInformation(202, [ref]$enabled, 1, [ref]$returned)
  if ($status -ne 0) { return $null }
  return ($enabled -ne 0)
}

$kernelDmaProtection = Get-KernelDmaProtectionState
if ($null -eq $kernelDmaProtection) {
  Write-Warning "[$scriptName] [skipped] Cannot determine the Kernel DMA Protection state; no change made."
  return
}
if ($kernelDmaProtection) {
  Write-Host "[$scriptName] [skipped] Kernel DMA Protection is enabled; Microsoft recommends not using this countermeasure."
  return
}

$settings = @(
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'DisableExternalDMAUnderLock'; Kind = 'DWord'; Value = 1 }
)

$hive = [Microsoft.Win32.RegistryHive]::LocalMachine
$basePath = ''
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
try {
  foreach ($setting in $settings) {
    $path = $basePath + $setting.Path
    $kind = [Microsoft.Win32.RegistryValueKind]$setting.Kind
    $key = $baseKey.CreateSubKey($path)
    if ($null -eq $key) { throw "[$scriptName] Cannot open HKLM:\$path." }
    try {
      $display = if ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { "$(@($setting.Value).Count) value(s)" } else { "$($setting.Value)" }
      $current = $null
      $currentKind = $null
      if ($key.GetValueNames() -contains $setting.Name) {
        $current = $key.GetValue($setting.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $currentKind = $key.GetValueKind($setting.Name)
      }
      if ($currentKind -eq $kind -and (@($current) -join '|') -eq (@($setting.Value) -join '|')) {
        Write-Host "[$scriptName] [Already configured] HKLM:\$path $($setting.Name) = $display ($kind)"
        continue
      }
      $before = if ($null -eq $currentKind) { 'not set' } elseif ($currentKind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { "$(@($current).Count) value(s) ($currentKind)" } else { "$current ($currentKind)" }
      $key.SetValue($setting.Name, $setting.Value, $kind)
      $actual = $key.GetValue($setting.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if ($key.GetValueKind($setting.Name) -ne $kind -or (@($actual) -join '|') -ne (@($setting.Value) -join '|')) {
        throw "[$scriptName] Verification failed: HKLM:\$path $($setting.Name)."
      }
      Write-Host "[$scriptName] [Was updated] HKLM:\$path $($setting.Name): $before -> $display ($kind)"
    }
    finally { $key.Dispose() }
  }
}
finally { $baseKey.Dispose() }
