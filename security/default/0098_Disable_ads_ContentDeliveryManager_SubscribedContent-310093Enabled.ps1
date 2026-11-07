<#
.SYNOPSIS
Disables the Windows welcome experience ("what's new and suggested") shown after updates and at sign-in for the current user.

.DESCRIPTION
Part of disabling ads in Windows 10/11 (Windows Consumer Features / app suggestions).
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager
  SubscribedContent-310093Enabled = 0 (DWORD)
  0 = disabled, 1 = Windows shows the welcome experience after updates and occasionally at sign-in.

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Creates the key if missing, then reads the value back to confirm it.
- To undo, set SubscribedContent-310093Enabled to 1.
- Related: 0075_Disassembler0_Win10-Initial-Setup-Script.ps1, 0037_Disable_Windows_Consumer_Features.bat
#>

$scriptName = "0098_Disable_ads_ContentDeliveryManager_SubscribedContent-310093Enabled"
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
$propertyName = "SubscribedContent-310093Enabled"
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
