<#
.SYNOPSIS
Denies the 3D Viewer app access to camera, microphone and location.

.DESCRIPTION
App: Microsoft.Microsoft3DViewer_8wekyb3d8bbwe!Microsoft.Microsoft3DViewer
Package SID: S-1-15-2-3739514657-3828455176-2936196785-2025316370-1894713875-3268641221-1640234959
(HKLM:\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.Microsoft3DViewer_*)

Sets Value = "Deny" (REG_SZ) on the app's DeviceAccess key and on these capabilities:
  {E5323777-F976-4f5b-9B55-B94699C46E44} - camera
  {2EEF81BE-33FA-4800-9670-1CD474972C3F} - microphone
  {BFA794E4-F964-4FDB-90F6-51056BFE4B44} - location

TODO: these values do not appear to remove 3D Viewer's device access permissions.
Mitigation: Get-AppxPackage Microsoft.Microsoft3DViewer | Remove-AppxPackage

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Legacy DeviceAccess location used by Windows 10 before 1903. Newer builds use
  HKCU/HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore
  and the AppPrivacy policy (see 0056_Disable_with_policy_apprivacy.ps1).
- Creates the key if missing, then reads the value back to confirm it.
- To undo, set Value to "Allow".
- Sources:
  https://www.joseespitia.com/2017/03/06/registry-keys-for-windows-10-privacy-settings/
  https://www.c-amie.co.uk/technical/windows-10-registry-paths-for-privacy-settings/
  https://www.ssi.gouv.fr/uploads/2017/01/np_securisation_windows10_collecte_de_donnees_v1.2.pdf
#>

$scriptName = "0088_017_Disable_device_access_for_Universal_Apps_3DViewer"
$appKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\S-1-15-2-3739514657-3828455176-2936196785-2025316370-1894713875-3268641221-1640234959"
$registryPaths = @(
  $appKey,
  "$appKey\{E5323777-F976-4f5b-9B55-B94699C46E44}",
  "$appKey\{2EEF81BE-33FA-4800-9670-1CD474972C3F}",
  "$appKey\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
)
$targetValue = "Deny"

foreach ($registryPath in $registryPaths) {
  if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $registryPath"
  }

  $property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties["Value"]
  $modified = $false
  if ($null -eq $property -or $property.Value -ne $targetValue) {
    Set-ItemProperty -Path $registryPath -Name "Value" -Value $targetValue -Type String -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name "Value" -ErrorAction Stop
  if ($confirmedValue -ne $targetValue) {
    throw "[$scriptName] Verification failed: $registryPath Value = $confirmedValue; expected $targetValue."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $registryPath Value = $confirmedValue"
}
