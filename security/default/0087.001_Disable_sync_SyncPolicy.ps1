<#
.SYNOPSIS
Turns off Windows settings sync for the current user (SyncPolicy = 5).

.DESCRIPTION
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync
  SyncPolicy = 5 (REG_DWORD).

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Split from 0087_Disable_sync.bat.
- Creates the key if missing, then reads the value back to confirm it.
- To undo: Delete the value or set it to 1 (sync on).
#>

$scriptName = "0087.001_Disable_sync_SyncPolicy"
$registryPaths = @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync")
$valueName = "SyncPolicy"
$targetValue = 5

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