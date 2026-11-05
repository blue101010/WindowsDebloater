<#
.SYNOPSIS
This script disables Cortana and modifies related registry values.

.DESCRIPTION
The script disables Cortana by setting various registry values to specific values. It checks if the registry values already exist and if their values need to be modified.
Missing registry keys are created before writing values. Registry access errors stop execution.

.PARAMETER path
The registry path where the property exists or needs to be created.

.PARAMETER propertyName
The name of the property to be modified or created.

.PARAMETER value
The value to set for the property.

.PARAMETER propertyType
The type of the property. Default value is "DWORD".

.EXAMPLE
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -PropertyName "AllowCortana" -Value 0

This example sets the "AllowCortana" property under the specified registry path to 0.

.NOTES
This script should be run with administrative privileges.
#>
function Set-RegistryValue {
    param(
        [string]$path,
        [string]$propertyName,
        [int]$value,
        [string]$propertyType = "DWORD"
    )

    if (-not (Test-Path -Path $path -ErrorAction Stop)) {
        Write-Host "[$propertyName] Registry path does not exist: $path. Creating it..."
        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
    }

    $properties = Get-ItemProperty -Path $path -ErrorAction Stop
    $property = $properties.PSObject.Properties[$propertyName]

    if ($null -eq $property) {
        # If the property doesn't exist, create it
        New-ItemProperty -Path $path -Name $propertyName -Value $value -PropertyType $propertyType -Force -ErrorAction Stop | Out-Null
        Write-Host "[$propertyName] created and set to $value"
    } elseif ($property.Value -ne $value) {
        # If the property exists and its value is not $value, set its value
        Set-ItemProperty -Path $path -Name $propertyName -Value $value -Type $propertyType -Force -ErrorAction Stop
        Write-Host "[$propertyName] adjusted to $value"
    } else {
        # If the property exists and its value is already $value
        Write-Host "[$propertyName] is already set to $value. No modification"
    }
}

# Disable Cortana
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -PropertyName "AllowCortana" -Value 0
