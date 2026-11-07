<#
.SYNOPSIS
Disables the UnistoreSvc (User Data Storage) per-user service.

.DESCRIPTION
Stores structured user data such as contacts, calendars and messages for Mail, Calendar and People.
It is a "protected" per-user service template: Set-Service / services.msc cannot change it,
so the Start value is written directly under
HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc
  Start = 4 (Disabled). Default is 3 (Manual).
Per-user instances (UnistoreSvc_<LUID>) inherit the template setting at the next sign-in.

.NOTES
- Run as Administrator (writes to HKLM). Takes effect after reboot or sign-out/sign-in.
- If the service is not installed, nothing is changed.
- Mail, Calendar and People apps may lose contact/calendar data access.
- To undo, set Start back to 3.
#>

$scriptName = "0089.002_Disable_protected_trash_services_UnistoreSvc"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc"
$propertyName = "Start"
$targetValue = 4

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  Write-Host "[$scriptName] [skipped] Service not installed: $registryPath"
  return
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$propertyName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $targetValue) {
  Set-ItemProperty -Path $registryPath -Name $propertyName -Value $targetValue -Type DWORD -Force -ErrorAction Stop
  $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $propertyName -ErrorAction Stop
if ($confirmedValue -ne $targetValue) {
  throw "[$scriptName] Verification failed: $registryPath $propertyName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $propertyName = $confirmedValue (disabled)"
