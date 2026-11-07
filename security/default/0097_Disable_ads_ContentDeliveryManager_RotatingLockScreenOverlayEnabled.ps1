<#
.SYNOPSIS
Disables "Get fun facts, tips, tricks, and more on your lock screen" (lock screen ads overlay) for the current user.

.DESCRIPTION
Part of disabling ads in Windows 10/11 (Windows Consumer Features / app suggestions).
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager
  RotatingLockScreenOverlayEnabled = 0 (DWORD)
  0 = disabled, 1 = tips and promotional overlays are shown on the lock screen.

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Creates the key if missing, then reads the value back to confirm it.
- To undo, set RotatingLockScreenOverlayEnabled to 1.
- Related: 0075_Disassembler0_Win10-Initial-Setup-Script.ps1, 0037_Disable_Windows_Consumer_Features.bat
#>

$scriptName = "0097_Disable_ads_ContentDeliveryManager_RotatingLockScreenOverlayEnabled"
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
$propertyName = "RotatingLockScreenOverlayEnabled"
$targetValue = 0

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Write-Host "[$scriptName] Created registry path: $registryPath"
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$propertyName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $targetValue) {
  Set-ItemProperty -Path $registryPath -Name $propertyName -Value $targetValue -Type DWORD -Force -ErrorAction Stop
  $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $propertyName -ErrorAction Stop
if ($confirmedValue -ne $targetValue) {
  throw "[$scriptName] Verification failed: $registryPath $propertyName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $propertyName = $confirmedValue (disabled)"
