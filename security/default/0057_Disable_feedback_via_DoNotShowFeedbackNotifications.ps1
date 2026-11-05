<#
.SYNOPSIS
Disables the display of feedback notifications in Windows 10.

.DESCRIPTION
This script checks if the registry key for disabling feedback notifications exists and sets its value to 1 if it is not already set. It provides feedback messages indicating the status of the registry key.
Missing keys and values are created as needed. DoNotShowFeedbackNotifications is written
as DWORD 1. Registry access errors stop execution; run as Administrator.

.PARAMETER None

.EXAMPLE
.\0057_Disable_feedback_via_DoNotShowFeedbackNotifications.ps1
This example runs the script and checks if the registry key for disabling feedback notifications exists. If it does not exist or its value is not set to 1, the script updates the value and displays a message indicating the status.

.NOTES
Author: [Your Name]
Date: [Current Date]
Version: 1.0
#>
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$registryValueName = "DoNotShowFeedbackNotifications"
$targetValue = 1

if (-not (Test-Path $registryPath -ErrorAction Stop)) {
  Write-Host "[0057_Disable_feedback_via_DoNotShowFeedbackNotifications] The registry key $registryPath does not exist. Creating it..."
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
}

$properties = Get-ItemProperty -Path $registryPath -ErrorAction Stop
$property = $properties.PSObject.Properties[$registryValueName]
if ($null -eq $property) {
  Write-Host "[0057_Disable_feedback_via_DoNotShowFeedbackNotifications] The value $registryValueName does not exist. Creating it..."
}

if ($null -eq $property -or $property.Value -ne $targetValue) {
  Set-ItemProperty -Path $registryPath -Name $registryValueName -Value $targetValue -Type DWORD -Force -ErrorAction Stop
  Write-Host "[0057_Disable_feedback_via_DoNotShowFeedbackNotifications] The value for $registryPath $registryValueName has been updated to $targetValue"
} else {
  Write-Host "[0057_Disable_feedback_via_DoNotShowFeedbackNotifications] The value for $registryPath $registryValueName is already set to $targetValue"
}
