<#
.SYNOPSIS
Keeps only English (United States) - United States-International for the current user.

.DESCRIPTION
Replaces the current user's preferred language list with en-US and the single
United States-International keyboard layout, then sets it as the default input
method. Removes Canadian Multilingual Standard (CMS) and all other layouts and
preferred language entries from this user's list.

.NOTES
- Current user only; administrator rights are not required.
- This changes preferred languages used by apps and websites, not just keyboards.
- Sign out and back in to refresh layouts cached by already-running applications.
- Does not uninstall system keyboard files or change other users/the sign-in screen.
- This is a one-time configuration, not a policy preventing later layout additions.
#>

$ErrorActionPreference = "Stop"
$scriptName = "0470_Set_default_input_method_English_US_International"
$languageTag = "en-US"
$inputTip = "0409:00020409"

$languageList = Get-WinUserLanguageList -ErrorAction Stop
$languageListChanged = $languageList.Count -ne 1 -or
  $languageList[0].LanguageTag -ne $languageTag -or
  $languageList[0].InputMethodTips.Count -ne 1 -or
  $languageList[0].InputMethodTips[0] -ne $inputTip

if ($languageListChanged) {
  $newLanguageList = New-WinUserLanguageList -Language $languageTag -ErrorAction Stop
  $newLanguageList[0].InputMethodTips.Clear()
  [void]$newLanguageList[0].InputMethodTips.Add($inputTip)
  Set-WinUserLanguageList -LanguageList $newLanguageList -Force -ErrorAction Stop
}

$currentOverride = Get-WinDefaultInputMethodOverride -ErrorAction Stop
$overrideChanged = $null -eq $currentOverride -or $currentOverride.InputMethodTip -ne $inputTip
if ($overrideChanged) {
  Set-WinDefaultInputMethodOverride -InputTip $inputTip -ErrorAction Stop
}

$confirmedLanguageList = Get-WinUserLanguageList -ErrorAction Stop
if ($confirmedLanguageList.Count -ne 1 -or
    $confirmedLanguageList[0].LanguageTag -ne $languageTag -or
    $confirmedLanguageList[0].InputMethodTips.Count -ne 1 -or
    $confirmedLanguageList[0].InputMethodTips[0] -ne $inputTip) {
  throw "[$scriptName] Verification failed: expected only $languageTag with input method $inputTip."
}

$confirmedOverride = Get-WinDefaultInputMethodOverride -ErrorAction Stop
if ($null -eq $confirmedOverride -or $confirmedOverride.InputMethodTip -ne $inputTip) {
  throw "[$scriptName] Verification failed: default input method is '$($confirmedOverride.InputMethodTip)'; expected $inputTip."
}

$layoutStatus = if ($languageListChanged) { "[changed]" } else { "[no change]" }
$overrideStatus = if ($overrideChanged) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $layoutStatus only $languageTag with United States-International ($inputTip); CMS and other layouts are absent."
Write-Host "[$scriptName] [confirmed] $overrideStatus default input method is United States-International ($inputTip)."
Write-Host "[$scriptName] Sign out and back in to refresh layouts in running applications."
