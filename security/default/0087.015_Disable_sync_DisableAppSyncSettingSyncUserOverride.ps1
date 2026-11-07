<#
.SYNOPSIS
Group Policy: prevent users from re-enabling sync of app sync (DisableAppSyncSettingSyncUserOverride = 1).

.DESCRIPTION
Sets HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync
  DisableAppSyncSettingSyncUserOverride = 1 (REG_DWORD).

.NOTES
- Machine-wide policy (HKLM); requires administrator rights.
- Split from 0087_Disable_sync.bat.
- Creates the key if missing, then reads the value back to confirm it.
- To undo: Delete the value (or set it to 0).
#>

$scriptName = "0087.015_Disable_sync_DisableAppSyncSettingSyncUserOverride"
$registryPaths = @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync")
$valueName = "DisableAppSyncSettingSyncUserOverride"
$targetValue = 1

foreach ($registryPath in $registryPaths) {
  if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $registryPath"
  }

  $property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$valueName]
  $modified = $false
  if ($null -eq $property -or $property.Value -ne $targetValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $targetValue -Type DWord -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $valueName -ErrorAction Stop
  if ($confirmedValue -ne $targetValue) {
    throw "[$scriptName] Verification failed: $registryPath $valueName = $confirmedValue; expected $targetValue."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $registryPath $valueName = $confirmedValue"
}