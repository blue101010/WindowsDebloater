<#
.SYNOPSIS
Disables Application Telemetry if it is enabled.

.DESCRIPTION
This script checks if the Application Telemetry is enabled in the Windows registry and disables it if necessary. It specifically looks for the "AITEnable" value under the "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" registry key. If the value is already set to 0 (disabled), no changes are made. If the value is set to any other value, it is updated to 0 to disable Application Telemetry.
Creates missing policy entries and sets AITEnable to DWORD 0.
Requests UAC elevation when needed. Registry errors stop execution and writes are verified.

.PARAMETER None

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
.\0017_Disable_Application_Telemetry.ps1
Approve the UAC prompt if the current PowerShell session is not elevated.

.NOTES
Author: [Your Name]
Date: [Current Date]
Version: 1.0
#>

$principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[0017_Disable_Application_Telemetry] Requesting administrator privileges through UAC..."
  $executableName = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
  $powerShellExecutable = Join-Path $PSHOME $executableName
  try {
    $elevatedProcess = Start-Process -FilePath $powerShellExecutable -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs -Wait -PassThru -ErrorAction Stop
  }
  catch {
    throw "Administrator elevation failed or was cancelled: $($_.Exception.Message)"
  }
  if ($elevatedProcess.ExitCode -ne 0) {
    throw "The elevated script failed with exit code $($elevatedProcess.ExitCode)."
  }
  return
}

$AppCompatPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
$propertyName = "AITEnable"
if (-not (Test-Path -Path $AppCompatPath -ErrorAction Stop)) {
  Write-Host "[0017_Disable_Application_Telemetry] - Registry folder $AppCompatPath does not exist. Creating it..."
  New-Item -Path $AppCompatPath -Force -ErrorAction Stop | Out-Null
}

$item = Get-ItemProperty -Path $AppCompatPath -ErrorAction Stop
$property = $item.PSObject.Properties[$propertyName]
if ($null -eq $property) {
  Write-Host "[0017_Disable_Application_Telemetry] $propertyName does not exist. Creating it..."
}
else {
  Write-Host "[0017_Disable_Application_Telemetry] Application Telemetry is currently set to $($property.Value)"
}

if ($null -eq $property -or $property.Value -ne 0) {
  Set-ItemProperty -Path $AppCompatPath -Name $propertyName -Value 0 -Type DWORD -Force -ErrorAction Stop
  $item = Get-ItemProperty -Path $AppCompatPath -ErrorAction Stop
  if ($item.$propertyName -ne 0) {
    throw "AITEnable verification failed: expected 0 after the registry write."
  }
  Write-Host "[0017_Disable_Application_Telemetry] Application Telemetry has been disabled"
}
else {
  Write-Host "[0017_Disable_Application_Telemetry] Application Telemetry is already disabled ($propertyName) [no change]"
}
