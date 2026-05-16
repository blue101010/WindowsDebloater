<#
.SYNOPSIS
Disables Bluetooth advertising beacons via the MDM policy registry key.

.DESCRIPTION
Sets AllowAdvertising = 0 (DWORD) under the Bluetooth PolicyManager key so that
Windows does not broadcast Bluetooth advertising packets.  The script checks the
current state first and only writes to the registry when a change is required,
then verifies the written value.

.PARAMETER None

.EXAMPLE
.\0177_Disable_advertisements_via_bluetooth.ps1

.NOTES
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth
Value:     AllowAdvertising = 0 (DWORD)
Applies to: Windows 10 / Windows 11
A sign-out/sign-in or reboot may be required for the policy to take full effect.
#>

# Elevation check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[0177_Disable_advertisements_via_bluetooth] This script requires elevation. Relaunching as Administrator in 3 seconds..."
  Start-Sleep -Seconds 3
  try {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction Stop
    exit
  }
  catch {
    Write-Warning "[0177_Disable_advertisements_via_bluetooth] Elevation failed or was denied: $_"
    Write-Host "[0177_Disable_advertisements_via_bluetooth] Please re-run this script as Administrator manually."
    exit 1
  }
}

$registryPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth'
$propertyName = 'AllowAdvertising'
$desiredValue = 0

# Create the registry key if it does not exist
if (-not (Test-Path $registryPath)) {
  Write-Host "[0177_Disable_advertisements_via_bluetooth] Registry key does not exist. Creating: $registryPath"
  New-Item -Path $registryPath -Force | Out-Null
}

# Read current state
$currentEntry = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

if ($null -eq $currentEntry) {
  Write-Host "[0177_Disable_advertisements_via_bluetooth] Current state : '$propertyName' does not exist."
}
else {
  Write-Host "[0177_Disable_advertisements_via_bluetooth] Current state : '$propertyName' = $($currentEntry.$propertyName)"
}

# Apply only if needed
if ($null -eq $currentEntry -or $currentEntry.$propertyName -ne $desiredValue) {
  New-ItemProperty -Path $registryPath `
                   -Name $propertyName `
                   -Value $desiredValue `
                   -PropertyType DWord `
                   -Force | Out-Null

  # Verify the write succeeded
  $written = (Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue).$propertyName
  if ($written -eq $desiredValue) {
    Write-Host "[0177_Disable_advertisements_via_bluetooth] CHANGED : '$propertyName' set to $desiredValue (verified)."
  }
  else {
    Write-Warning "[0177_Disable_advertisements_via_bluetooth] FAILED  : '$propertyName' could not be verified (read back: $written)."
    exit 1
  }
}
else {
  Write-Host "[0177_Disable_advertisements_via_bluetooth] No change : '$propertyName' is already $desiredValue."
}

Write-Host "[0177_Disable_advertisements_via_bluetooth] A sign-out/sign-in or reboot may be required for full effect."

Read-Host "`nPress Enter to close..."