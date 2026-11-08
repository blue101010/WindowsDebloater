<#
.SYNOPSIS
Disables (default) or enables (-Enable) the Windows optional feature "IIS-HttpTracing".

.DESCRIPTION
Converted from 0132_Disable_windows-features.bat
(Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpTracing).

Status output:
  [Not available]      the feature does not exist on this Windows edition or build; nothing is changed
  [Already configured] the feature is already in the requested state
  [Was updated]        the feature state was changed (restart may be required)

.PARAMETER Enable
Enables the feature instead of disabling it (also enables required parent features).
A feature whose payload was removed may need Windows Update or installation media.

.NOTES
Run as Administrator. No automatic restart.

.EXAMPLE
.\0132.025_Disable_windows_feature_IIS-HttpTracing.ps1
.EXAMPLE
.\0132.025_Disable_windows_feature_IIS-HttpTracing.ps1 -Enable
#>
[CmdletBinding()]
param([switch]$Enable)

$scriptName = "0132.025_Disable_windows_feature_IIS-HttpTracing"
$featureName = "IIS-HttpTracing"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "[$scriptName] Run this script as Administrator."
}

$feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
if ($null -eq $feature) {
  Write-Host "[$scriptName] [Not available] Feature $featureName does not exist on this system; nothing changed."
  return
}

if ($Enable) {
  $targetStates = @('Enabled', 'EnablePending')
  $action = 'enable'
}
else {
  $targetStates = @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending')
  $action = 'disable'
}

if ("$($feature.State)" -in $targetStates) {
  Write-Host "[$scriptName] [Already configured] Feature $featureName state = $($feature.State)"
  return
}

$before = $feature.State
if ($Enable) {
  $result = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart -ErrorAction Stop
}
else {
  $result = Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop
}
$after = (Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop).State
if ("$after" -notin $targetStates) {
  throw "[$scriptName] Verification failed: could not $action feature $featureName (state = $after)."
}
$restart = if ($result.RestartNeeded -or "$after" -like '*Pending') { ' (restart required)' } else { '' }
Write-Host "[$scriptName] [Was updated] Feature ${featureName}: $before -> $after$restart"