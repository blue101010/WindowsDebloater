<#
.SYNOPSIS
This script disables the save and fill of address functionality in the Brave browser by modifying the registry settings.

.DESCRIPTION
The script checks if the registry key for Brave exists and creates it if it doesn't.
Sets AutofillAddressEnabled to DWORD 0 for the current user and reads it back
before confirming status. Registry access and verification failures stop execution.

.PARAMETER None

.EXAMPLE
Runs the script to disable save and fill functionality in Brave.

.NOTES
Author: [Author Name]
Date: [Date]
Version: [Version]
#>

# Define the registry path
$BravePolicyPath = "HKCU:\Software\Policies\BraveSoftware\Brave"


Function Set-BravePolicy {
    param (
        [string]$Key,
        [int]$Value
    )
    if (-not (Test-Path -LiteralPath $BravePolicyPath -ErrorAction Stop)) {
        Write-Host "[0394_Disable_Brave_AutofillAddressEnabled] Registry key missing: $BravePolicyPath. Creating it..."
        New-Item -Path $BravePolicyPath -Force -ErrorAction Stop | Out-Null
    }
    $properties = Get-ItemProperty -Path $BravePolicyPath -ErrorAction Stop
    $property = $properties.PSObject.Properties[$Key]
    $status = "no change"
    if ($null -eq $property -or $property.Value -ne $Value) {
        Set-ItemProperty -Path $BravePolicyPath -Name $Key -Value $Value -Type DWORD -Force -ErrorAction Stop
        $status = "changed"
    }
    $confirmedValue = Get-ItemPropertyValue -Path $BravePolicyPath -Name $Key -ErrorAction Stop
    if ($null -eq $confirmedValue -or $confirmedValue -ne $Value) {
        throw "[0394_Disable_Brave_AutofillAddressEnabled] Verification failed: $Key = '$confirmedValue'; expected $Value."
    }
    Write-Host "[0394_Disable_Brave_AutofillAddressEnabled] [confirmed] [$status] $Key = $confirmedValue (disabled)"
}

Set-BravePolicy -Key "AutofillAddressEnabled" -Value 0

# Output the current settings
Write-Host "[0394_Disable_Brave_AutofillAddressEnabled] Current config is so : "
Get-ItemProperty -Path $BravePolicyPath -ErrorAction Stop
