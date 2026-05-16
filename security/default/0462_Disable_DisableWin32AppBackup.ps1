<#
.SYNOPSIS
Disables the Win32 App Backup (DisableWin32AppBackup) feature in Windows.

.DESCRIPTION
This script disables the Win32 App Backup inventory feature in Windows by setting the
'DisableWin32AppBackup' DWORD value to 1 under the AppCompat policy registry key.
It reports the current state before making any change, and only writes to the
registry if the value is not already set correctly.

.PARAMETER None

.EXAMPLE
.\0462_Disable_DisableWin32AppBackup.ps1
This command runs the script and disables the Win32 App Backup feature.

.NOTES
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat
Value:     DisableWin32AppBackup = 1 (DWORD)
Applies to: Windows 10 / Windows 11
#>
# Disable Win32 App Backup (app/device inventory feature)

# Elevation check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[0462_Disable_DisableWin32AppBackup] This script requires elevation. Relaunching as Administrator in 3 seconds..."
  Start-Sleep -Seconds 3
  try {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction Stop
    exit
  }
  catch {
    Write-Warning "[0462_Disable_DisableWin32AppBackup] Elevation failed or was denied: $_"
    Write-Host "[0462_Disable_DisableWin32AppBackup] Please re-run this script as Administrator manually."
    exit 1
  }
}

$registryPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
$propertyName  = "DisableWin32AppBackup"
$desiredValue  = 1

# Create the registry key if it does not exist
if (!(Test-Path $registryPath)) {
  Write-Host "[0462_Disable_DisableWin32AppBackup] Registry key does not exist. Creating: $registryPath"
  New-Item -Path $registryPath -Force | Out-Null
}

# Read current state
$currentEntry = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

if ($null -eq $currentEntry) {
  Write-Host "[0462_Disable_DisableWin32AppBackup] Current state : '$propertyName' does not exist."
}
else {
  Write-Host "[0462_Disable_DisableWin32AppBackup] Current state : '$propertyName' = $($currentEntry.$propertyName)"
}

# Apply only if needed
if ($null -eq $currentEntry -or $currentEntry.$propertyName -ne $desiredValue) {
  New-ItemProperty -Path $registryPath `
                   -Name $propertyName `
                   -Value $desiredValue `
                   -PropertyType DWord `
                   -Force | Out-Null
  Write-Host "[0462_Disable_DisableWin32AppBackup] CHANGED : '$propertyName' set to $desiredValue."
}
else {
  Write-Host "[0462_Disable_DisableWin32AppBackup] No change : '$propertyName' is already $desiredValue."
}

Read-Host "`nPress Enter to close..."
