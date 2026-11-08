<#
.SYNOPSIS
Enables Microsoft Defender Antivirus email scanning during scheduled and on-demand scans.

.DESCRIPTION
Sets the DisableEmailScanning policy to 0. Email scanning has limited format
support and does not replace real-time protection or modern mail filtering.
CIS (L1) "Turn on e-mail scanning", extracted from 0181_WynisWIN10-CISv1.0.ps1.

.NOTES
Windows 11; run as Administrator. Defender must be available and active.
Managed policies or tamper protection can prevent or override this setting.
Writing the registry value alone does not prove that the effective policy is applied.
To undo, delete the DisableEmailScanning value.
https://learn.microsoft.com/en-us/defender-endpoint/configure-advanced-scan-types-microsoft-defender-antivirus
#>

$scriptName = "0481_Enable_Defender_email_scanning"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$registryPath = "SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$valueName = "DisableEmailScanning"
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
  $key = $baseKey.CreateSubKey($registryPath)
  if ($null -eq $key) { throw "[$scriptName] Cannot open HKLM:\$registryPath." }
  try {
    if ($key.GetValueNames() -contains $valueName -and $key.GetValueKind($valueName) -eq [Microsoft.Win32.RegistryValueKind]::DWord -and $key.GetValue($valueName) -eq 0) {
      Write-Host "[$scriptName] [Already configured] HKLM:\$registryPath $valueName = 0 (DWord). Verify the effective Defender policy separately."
      return
    }
    $before = if ($key.GetValueNames() -contains $valueName) { "$($key.GetValue($valueName)) ($($key.GetValueKind($valueName)))" } else { 'not set' }
    $key.SetValue($valueName, 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    if ($key.GetValue($valueName) -ne 0 -or $key.GetValueKind($valueName) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
      throw "[$scriptName] Registry verification failed for $valueName."
    }
    Write-Host "[$scriptName] [Was updated] HKLM:\$registryPath ${valueName}: $before -> 0 (DWord). Verify the effective Defender policy separately."
  }
  finally { $key.Dispose() }
}
finally { $baseKey.Dispose() }
