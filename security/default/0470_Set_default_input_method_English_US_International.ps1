<#
.SYNOPSIS
Sets English (United States) - United States-International as the current user's default input method.

.DESCRIPTION
Adds the United States-International keyboard layout to the current user's en-US
language entry if it is not already present, then sets it as the default input
method. Existing languages and keyboard layouts are preserved.

.NOTES
- Current user only; administrator rights are not required.
- Sign out and back in if the input indicator does not update immediately.
#>

$ErrorActionPreference = "Stop"
$scriptName = "0470_Set_default_input_method_English_US_International"
$languageTag = "en-US"
$inputTip = "0409:00020409"

$languageList = Get-WinUserLanguageList -ErrorAction Stop
$englishLanguage = $languageList | Where-Object { $_.LanguageTag -eq $languageTag } | Select-Object -First 1
$languageListChanged = $false

if ($null -eq $englishLanguage) {
  $newEnglishLanguage = New-WinUserLanguageList -Language $languageTag -ErrorAction Stop
  [void]$languageList.Add($newEnglishLanguage[0])
  $englishLanguage = $newEnglishLanguage[0]
  $languageListChanged = $true
}

if ($englishLanguage.InputMethodTips -notcontains $inputTip) {
  [void]$englishLanguage.InputMethodTips.Add($inputTip)
  $languageListChanged = $true
}

if ($languageListChanged) {
  Set-WinUserLanguageList -LanguageList $languageList -Force -ErrorAction Stop
}

$currentOverride = Get-WinDefaultInputMethodOverride -ErrorAction Stop
$overrideChanged = $null -eq $currentOverride -or $currentOverride.InputTip -ne $inputTip
if ($overrideChanged) {
  Set-WinDefaultInputMethodOverride -InputTip $inputTip -ErrorAction Stop
}

$confirmedLanguage = Get-WinUserLanguageList -ErrorAction Stop |
  Where-Object { $_.LanguageTag -eq $languageTag } |
  Select-Object -First 1
if ($null -eq $confirmedLanguage -or $confirmedLanguage.InputMethodTips -notcontains $inputTip) {
  throw "[$scriptName] Verification failed: $languageTag does not include input method $inputTip."
}

$confirmedOverride = Get-WinDefaultInputMethodOverride -ErrorAction Stop
if ($null -eq $confirmedOverride -or $confirmedOverride.InputTip -ne $inputTip) {
  throw "[$scriptName] Verification failed: default input method is not $inputTip."
}

$layoutStatus = if ($languageListChanged) { "[changed]" } else { "[no change]" }
$overrideStatus = if ($overrideChanged) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $layoutStatus $languageTag includes United States-International ($inputTip)."
Write-Host "[$scriptName] [confirmed] $overrideStatus default input method is United States-International ($inputTip)."
