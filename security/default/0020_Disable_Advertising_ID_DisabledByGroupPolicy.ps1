<#
.SYNOPSIS
Disables the Advertising ID feature in Windows 10/11.

.DESCRIPTION
This script disables the Advertising ID feature in Windows 10 by modifying the corresponding registry keys.
The Advertising ID is used by Microsoft to personalize ads and recommendations on Windows devices.
Creates the AdvertisingInfo policy key if needed and sets DisabledByGroupPolicy to DWORD 1
when missing or not already 1. Registry access errors stop execution; run as Administrator.

.PARAMETER None

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Disable-AdvertisingID

.NOTES
Author: [Your Name]
Date: [Current Date]
Version: 1.0
#>

# DisabledByGroupPolicy: 1 disables the Advertising ID.
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
$registryProperty = "DisabledByGroupPolicy"

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  Write-Host "[0020_Disable_Advertising_ID_DisabledByGroupPolicy] Windows\AdvertisingInfo path does not exist. Creating it..."
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
}

$properties = Get-ItemProperty -Path $registryPath -ErrorAction Stop
$property = $properties.PSObject.Properties[$registryProperty]
if ($null -eq $property) {
  Write-Host "[0020_Disable_Advertising_ID_DisabledByGroupPolicy] $registryProperty does not exist. Creating it..."
}

if ($null -eq $property -or $property.Value -ne 1) {
  Set-ItemProperty -Path $registryPath -Name $registryProperty -Value 1 -Type DWORD -Force -ErrorAction Stop
  Write-Host "[0020_Disable_Advertising_ID_DisabledByGroupPolicy] Windows\AdvertisingInfo $registryProperty  was set to 1"
}
else {
  Write-Host "[0020_Disable_Advertising_ID_DisabledByGroupPolicy] Windows\AdvertisingInfo $registryProperty  was already set [no change]"
}
