<#
.SYNOPSIS
Disables the Inventory Collector feature in Windows.

.DESCRIPTION
This script disables the Inventory Collector feature in Windows by modifying the corresponding registry key.
It checks the initial value of the 'DisableInventory' property in the registry and sets it to 1 if it is not already set.

.PARAMETER None

.EXAMPLE
.\0018_Disable_Inventory_Collector.ps1
This command runs the script and disables the Inventory Collector feature.

.NOTES
Author: [Author Name]
Date: [Date]
Version: [Version Number]
#>
# Disable Inventory Collector

# Elevation check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[0018_Disable_Inventory_Collector] This script requires elevation. Relaunching as Administrator in 3 seconds..."
  Start-Sleep -Seconds 3
  try {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction Stop
    exit
  }
  catch {
    Write-Warning "[0018_Disable_Inventory_Collector] Elevation failed or was denied: $_"
    Write-Host "[0018_Disable_Inventory_Collector] Please re-run this script as Administrator manually."
    exit 1
  }
}

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"

if (!(Test-Path $registryPath)) {
  Write-Host "[0018_Disable_Inventory_Collector] - Registry folder $registryPath does not exist. Creating it..."
  New-Item -Path $registryPath -Force | Out-Null
}


$propertyName = "DisableInventory"
$initialValue = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

if ($null -eq $initialValue) {
  Write-Host "[0018_Disable_Inventory_Collector] The property '$propertyName' does not exist in the registry."
}
else {
  Write-Host "[0018_Disable_Inventory_Collector] The initial value of '$propertyName' is $($initialValue.$propertyName)."
}

if ($null -eq $initialValue -or $initialValue.$propertyName -ne 1) {
  Set-ItemProperty -Path $registryPath -Name $propertyName -Value 1
  Write-Host "[0018_Disable_Inventory_Collector] The value of '$propertyName' has been set to 1."
}
else {
  Write-Host "[0018_Disable_Inventory_Collector] The value of '$propertyName' is already 1. [No change]"
}

Read-Host "`nPress Enter to close..."

