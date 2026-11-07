# Disable Advertising ID for Relevant Ads
# Advertising ID Let Apps use for Relevant Ads in Windows 10...
# Windows Registry Editor Version 5.00
# [HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo]
# "Enabled"=dword:00000000
# Enabled = 1 - the feature is enabled : you share the Ad ID...
# Enabled = 0 - the feature is disabled.
# Reads back Enabled to confirm the configured value. Run as Administrator for HKLM.

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
$propertyName = "Enabled"
$targetValue = 0
$modified = $false

if (-not (Test-Path $registryPath -ErrorAction Stop)) {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Write-Host "[0025_Disable_Advertising_ID_for_Relevant_Ads_Enabled] Created registry path: $registryPath"
}

$properties = Get-ItemProperty -Path $registryPath -ErrorAction Stop
$property = $properties.PSObject.Properties[$propertyName]
if ($null -eq $property -or $property.Value -ne $targetValue) {
  Set-ItemProperty -Path $registryPath -Name $propertyName -Value $targetValue -Type DWORD -Force -ErrorAction Stop
  $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $propertyName -ErrorAction Stop
if ($confirmedValue -ne $targetValue) {
  throw "[0025_Disable_Advertising_ID_for_Relevant_Ads_Enabled] Verification failed: $registryPath $propertyName = $confirmedValue; expected $targetValue."
}

if ($modified) {
  Write-Host "[0025_Disable_Advertising_ID_for_Relevant_Ads_Enabled] [confirmed] [changed] $registryPath $propertyName = $confirmedValue (disabled)"
}
else {
  Write-Host "[0025_Disable_Advertising_ID_for_Relevant_Ads_Enabled] [confirmed] [no change] $registryPath $propertyName = $confirmedValue (disabled)"
}
