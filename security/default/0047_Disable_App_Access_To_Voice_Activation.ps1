<#
.SYNOPSIS
Disables app access to voice activation in Windows 10.

.DESCRIPTION
This script disables app access to voice activation by modifying the registry settings. It creates the registry path and property if missing, updates the value if it differs from the desired value, and reads it back to confirm.

.PARAMETER registryPath
The registry path where the property is located.

.PARAMETER propertyName
The name of the property to be modified.

.PARAMETER desiredValue
The desired value to set for the property.

.NOTES
- This script should be run with administrative privileges.
- It is recommended to create a backup of the registry before running this script.

.EXAMPLE
Disable-AppAccessToVoiceActivation -registryPath "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -propertyName "AgentActivationEnabled" -desiredValue 0
#>

$registryPath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"
$propertyName = "AgentActivationEnabled"
$desiredValue = 0

$scriptName = "0047_Disable_App_Access_To_Voice_Activation"

if (-not (Test-Path $registryPath -ErrorAction Stop)) {
    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $registryPath"
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$propertyName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $desiredValue) {
    Set-ItemProperty -Path $registryPath -Name $propertyName -Value $desiredValue -Type DWORD -Force -ErrorAction Stop
    $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $propertyName -ErrorAction Stop
if ($confirmedValue -ne $desiredValue) {
    throw "[$scriptName] Verification failed: $registryPath $propertyName = $confirmedValue; expected $desiredValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $propertyName = $confirmedValue (disabled)"
