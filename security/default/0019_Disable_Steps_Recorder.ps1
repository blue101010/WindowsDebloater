<#
.SYNOPSIS
Disables the Steps Recorder feature in Windows.
# Disable Steps Recorder 
# Steps Recorder (called Problems Steps Recorder in Windows , is a program that helps you troubleshoot 
# a problem on your device by recording the exact steps you took when the problem occurred

.DESCRIPTION
This script checks if the registry key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" exists. If it exists, it checks the "DisableUAR" property without requiring it to be present. If the property is missing or its value is not already 1, it sets the DWORD value to 1. The script reports missing properties and whether the value was changed. If the registry key is missing, it exits without creating it. Registry access errors stop execution; run as Administrator to write the policy.

.PARAMETER None

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Disable-StepsRecorder

This example demonstrates how to use the script to disable the Steps Recorder feature in Windows.

.NOTES
Author: [Author Name]
Date: [Date]
Version: [Version Number]
#>
# Check if registry key exists
$testpath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
if (Test-Path $testpath -ErrorAction Stop) {
  # Get the current value of DisableUAR
  $properties = Get-ItemProperty -Path $testpath -ErrorAction Stop
  $property = $properties.PSObject.Properties["DisableUAR"]
  $currentValue = $null
  if ($null -eq $property) {
    Write-Host "[0019_Disable_Steps_Recorder] The property 'DisableUAR' does not exist in the registry."
  } else {
    $currentValue = $property.Value
  
    # Display the initial value
    Write-Host "[0019_Disable_Steps_Recorder] Initial value of DisableUAR: $currentValue"
  }
  
  # Set the value to 1 only if it is not already set to 1
  if ($null -eq $property -or $currentValue -ne 1) {
    Set-ItemProperty -Path $testpath -Name "DisableUAR" -Value 1 -Type DWORD -Force -ErrorAction Stop
    Write-Host "[0019_Disable_Steps_Recorder] DisableUAR was set to 1."
  } else {
    Write-Host "[0019_Disable_Steps_Recorder] DisableUAR is already set to 1 [no change]."
  }
}
else {
  Write-Host "[0019_Disable_Steps_Recorder] Registry folder $testpath does not exist. Exiting..."
  return
}

