# Disable keylogger InputPersonalization

<#
.SYNOPSIS
This script disables the keylogger InputPersonalization by modifying registry values.

.DESCRIPTION
The script contains a function called Test-And-Set-RegistryItem, which tests and sets the value of a registry item.
It then calls the Test-And-Set-RegistryItem function multiple times to disable various keylogger settings.
Missing registry keys and values are created as needed. Values are written as DWORDs.
Registry access errors stop execution; run as Administrator to update HKLM policies.

.PARAMETER Path
The registry path where the item is located.

.PARAMETER Name
The name of the registry item.

.PARAMETER Value
The value to set for the registry item.

.NOTES
Author: [Author Name]
Date: [Date]
Version: [Version]

.EXAMPLE
Test-And-Set-RegistryItem -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
# Tests and sets the value of the registry item "RestrictImplicitInkCollection" to 1 in the specified path.

#>

# Test and set registry item value
function Test-And-Set-RegistryItem {
  param (
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [int]$Value
  )

  if (-not (Test-Path -Path $Path -ErrorAction Stop)) {
    Write-Host "[0021_Disable_keylogger_InputPersonalization] Item does not exist: $Path. Creating it..."
    New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
  }

  $properties = Get-ItemProperty -Path $Path -ErrorAction Stop
  $property = $properties.PSObject.Properties[$Name]
  if ($null -eq $property) {
    Write-Host "[0021_Disable_keylogger_InputPersonalization] Value does not exist: $Path\$Name. Creating it..."
  }

  if ($null -eq $property -or $property.Value -ne $Value) {
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -Force -ErrorAction Stop
    Write-Host "[0021_Disable_keylogger_InputPersonalization] Value changed for $Path\$Name to $Value"
  }
  else {
    Write-Host "[0021_Disable_keylogger_InputPersonalization] No change for $Path\$Name with value $Value"
  }
}

# Disable keylogger InputPersonalization
$testResults = @(
  (Test-And-Set-RegistryItem -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0),
  (Test-And-Set-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1),
  (Test-And-Set-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0)
)

$testResults | ForEach-Object {
  Write-Host "[0021_Disable_keylogger_InputPersonalization] $_"
}
