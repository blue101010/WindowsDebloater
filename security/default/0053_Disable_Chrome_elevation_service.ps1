<#
.SYNOPSIS
Keeps the Google Chrome Elevation Service on manual start and stops it if running.

.DESCRIPTION
GoogleChromeElevationService is installed with system-level Google Chrome. It runs as
LocalSystem and is used by Chrome to perform privileged operations, such as the Chrome
recovery component and app-bound encryption of cookies/passwords (Chrome 127+).

Sets under HKLM:\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService
  Start = 3 (DWORD)  Manual: starts only when Chrome requests it (2 = Automatic, 4 = Disabled)
  Type  = 16 (DWORD) 0x10, Win32 service running in its own process (Chrome's default)
Then stops the service if it is running.

Manual is used instead of Disabled because Chrome relies on the service on demand;
disabling it can break Chrome's app-bound encryption and recovery.

.NOTES
- Run as Administrator (writes to HKLM and stops a service).
- If the service is not installed, nothing is changed.
- Chrome updates may reset these values.
- Reference: https://support.google.com/chrome/thread/189935188/what-is-google-chrome-elevation-service-do-you-know?hl=en
#>

$scriptName = "0053_Disable_Chrome_elevation_service"
$serviceName = "GoogleChromeElevationService"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$targetValues = [ordered]@{
  Start = 3
  Type  = 16
}

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  Write-Host "[$scriptName] [skipped] Service not installed: $registryPath"
  return
}

foreach ($name in $targetValues.Keys) {
  $targetValue = $targetValues[$name]
  $property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$name]
  $modified = $false
  if ($null -eq $property -or $property.Value -ne $targetValue) {
    Set-ItemProperty -Path $registryPath -Name $name -Value $targetValue -Type DWORD -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $name -ErrorAction Stop
  if ($confirmedValue -ne $targetValue) {
    throw "[$scriptName] Verification failed: $registryPath $name = $confirmedValue; expected $targetValue."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $registryPath $name = $confirmedValue"
}

$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne "Stopped") {
  Stop-Service -Name $serviceName -Force -ErrorAction Stop
  $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
  Write-Host "[$scriptName] [confirmed] [changed] Service $serviceName stopped"
}
else {
  Write-Host "[$scriptName] [confirmed] [no change] Service $serviceName already stopped"
}
