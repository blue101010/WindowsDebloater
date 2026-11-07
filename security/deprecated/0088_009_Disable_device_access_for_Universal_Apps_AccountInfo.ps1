<#
.SYNOPSIS
Denies Universal (Store) apps device access: Let apps access my name, picture and other account info.

.DESCRIPTION
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}
  Value = "Deny" (REG_SZ). "Allow" re-enables access.

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

$scriptName = "0088_009_Disable_device_access_for_Universal_Apps_AccountInfo"
$registryPaths = @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}")
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
