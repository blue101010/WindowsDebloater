<#
.SYNOPSIS
Disables syncing of other Windows settings for the current user (SettingSync group Windows).

.DESCRIPTION
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows
  Enabled = 0 (REG_DWORD).

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Split from 0087_Disable_sync.bat.
- Creates the key if missing, then reads the value back to confirm it.
- To undo: Set Enabled to 1.
#>

$scriptName = "0087.011_Disable_sync_Groups_Windows_Enabled"
$registryPaths = @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows")
$valueName = "Enabled"
$targetValue = 0

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