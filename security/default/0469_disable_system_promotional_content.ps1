<#
.SYNOPSIS
Disables system promotional content pushed through ContentDeliveryManager: silent app
installs, Start suggestions, tips, and Settings app suggestions.

.DESCRIPTION
Windows uses the ContentDeliveryManager key to push background promotions, pre-installed
app shortcuts and silent app installations. Sets these DWORD values to 0 under
HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager:

  SilentInstalledAppsEnabled       - Silent installation of suggested/sponsored apps
  SystemPaneSuggestionsEnabled     - Suggested apps in Start ("Show suggestions occasionally in Start")
  SubscribedContent-338388Enabled  - Suggestions in Start
  SubscribedContent-338389Enabled  - "Get tips, tricks, and suggestions as you use Windows"
  SubscribedContent-353696Enabled  - Suggested content in the Settings app
  SubscribedContent-338393Enabled  - Suggested content in the Settings app

0 = off, 1 / missing = on.

.NOTES
- Current user only (HKCU); no administrator rights needed.
- Apps already installed silently are not removed.
- Creates the key and values if missing, then reads each value back to confirm it.
- To undo, set the values to 1.
- Overlaps: 0037 (SystemPaneSuggestionsEnabled), 0290 (SilentInstalledAppsEnabled),
  0291 (SubscribedContent-*), 0095-0098 (other ContentDeliveryManager values).
- References:
  https://www.pdq.com/blog/how-to-disable-ads-on-windows/
  https://winaero.com/how-to-disable-ads-in-windows-11/
#>

$scriptName = "0469_disable_system_promotional_content"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
$valueNames = @(
  "SilentInstalledAppsEnabled",
  "SystemPaneSuggestionsEnabled",
  "SubscribedContent-338388Enabled",
  "SubscribedContent-338389Enabled",
  "SubscribedContent-353696Enabled",
  "SubscribedContent-338393Enabled"
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
