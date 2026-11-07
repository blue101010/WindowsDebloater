<#
.SYNOPSIS
Turns off Windows location services and sensors machine-wide through Group Policy registry values.

.DESCRIPTION
Equivalent to "Computer Configuration > Administrative Templates > Windows Components >
Location and Sensors" policies. Sets these DWORD values to 1 under
HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors:
  DisableLocation                - Turn off location (no app or service can use location)
  DisableLocationScripting       - Turn off location scripting
  DisableSensors                 - Turn off sensors
  DisableWindowsLocationProvider - Turn off the Windows Location Provider

.NOTES
- Run as Administrator (writes to HKLM).
- Creates the key and values if missing, then reads each value back to confirm it.
- Location-dependent features (Find my device, maps, weather, auto time zone) stop working.
#>

$scriptName = "0086_Disable_location_access_and_sensors"
$locationKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
$targetValue = 1
$valueNames = @(
    "DisableLocation",
    "DisableLocationScripting",
    "DisableSensors",
    "DisableWindowsLocationProvider"
)

if (-not (Test-Path -Path $locationKeyPath -ErrorAction Stop)) {
    New-Item -Path $locationKeyPath -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $locationKeyPath"
}

foreach ($name in $valueNames) {
    $property = (Get-ItemProperty -Path $locationKeyPath -ErrorAction Stop).PSObject.Properties[$name]
    $modified = $false
    if ($null -eq $property -or $property.Value -ne $targetValue) {
        Set-ItemProperty -Path $locationKeyPath -Name $name -Value $targetValue -Type DWORD -Force -ErrorAction Stop
        $modified = $true
    }

    $confirmedValue = Get-ItemPropertyValue -Path $locationKeyPath -Name $name -ErrorAction Stop
    if ($confirmedValue -ne $targetValue) {
        throw "[$scriptName] Verification failed: $locationKeyPath $name = $confirmedValue; expected $targetValue."
    }

    $status = if ($modified) { "[changed]" } else { "[no change]" }
    Write-Host "[$scriptName] [confirmed] $status $locationKeyPath $name = $confirmedValue"
}
