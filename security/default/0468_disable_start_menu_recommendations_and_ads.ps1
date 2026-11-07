<#
.SYNOPSIS
Disables Windows 11 Start menu recommendations (promoted apps/tips) and account-related promotional notifications.

.DESCRIPTION
Sets these DWORD values to 0 under
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced:

  Start_IrisRecommendations  = 0
    Settings > Personalization > Start > "Show recommendations for tips, shortcuts, new apps, and more".
    Removes app and layout recommendations / ad tiles from the Recommended section.

  Start_AccountNotifications = 0
    Settings > Personalization > Start > "Show account-related notifications".
    Removes Microsoft account / OneDrive / Microsoft 365 promotions from the Start menu.

0 = off, 1 / missing = on.

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Restart Explorer or sign out/in if the Start menu does not refresh.
- Creates the key and values if missing, then reads each value back to confirm it.
- To undo, set the values to 1.
- Related: 0291_Disable_Get_even_more_SubscribedContent.bat (Windows 10 Start suggestions),
  0467_disable_search_highlights.ps1
#>

$scriptName = "0468_disable_start_menu_recommendations_and_ads"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$valueNames = @(
  "Start_IrisRecommendations",
  "Start_AccountNotifications"
)
$targetValue = 0

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Write-Host "[$scriptName] Created registry path: $registryPath"
}

foreach ($name in $valueNames) {
  $property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$name]
  $modified = $false
  if ($null -eq $property -or $property.Value -ne $targetValue) {
    Set-ItemProperty -Path $registryPath -Name $name -Value $targetValue -Type DWORD -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $name -ErrorAction Stop
  if ($confirmedValue -ne $targetValue) {
    throw "[$scriptName] Verification failed: $registryPath $name = $confirmedValue; expected $targetValue."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $registryPath $name = $confirmedValue (disabled)"
}
