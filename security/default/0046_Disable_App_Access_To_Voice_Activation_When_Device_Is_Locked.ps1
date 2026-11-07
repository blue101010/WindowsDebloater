<#
.SYNOPSIS
Disables app access to voice activation when the device is locked.

.DESCRIPTION
This script disables the ability for apps to access voice activation when the device is locked. It creates the registry key if missing, updates the value if necessary, and reads it back to confirm.

.PARAMETER registryPath
The path to the registry key that controls app access to voice activation when the device is locked.

.PARAMETER registryValueName
The name of the registry value that controls app access to voice activation when the device is locked.

.PARAMETER targetValue
The desired value for the registry key. If the current value is different from the target value, the script will update it.

.NOTES
- This script requires administrative privileges to modify the registry.
- The registry key and value names may vary depending on the Windows version.

.EXAMPLE
Disable-AppAccessToVoiceActivation -registryPath "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -registryValueName "AgentActivationOnLockScreenEnabled" -targetValue 0
#>
$registryPath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"
$registryValueName = "AgentActivationOnLockScreenEnabled"
$targetValue = 0

$scriptName = "0046_Disable_App_Access_To_Voice_Activation_When_Device_Is_Locked"

if (-not (Test-Path $registryPath -ErrorAction Stop)) {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Write-Host "[$scriptName] Created registry path: $registryPath"
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$registryValueName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $targetValue) {
  Set-ItemProperty -Path $registryPath -Name $registryValueName -Value $targetValue -Type DWORD -Force -ErrorAction Stop
  $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $registryValueName -ErrorAction Stop
if ($confirmedValue -ne $targetValue) {
  throw "[$scriptName] Verification failed: $registryPath $registryValueName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $registryValueName = $confirmedValue (disabled)"
