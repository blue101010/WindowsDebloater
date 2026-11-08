$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$archivedNames = @(
    "0036.01_Disable_cortana_registry_AllowCortana.ps1",
    "0036.02_Disable_cortana_registry_DisableWebSearch.ps1",
    "0077_Disable_Microsoft_Windows_Maps_sched_task.ps1",
    "0088_001_Disable_device_access_for_Universal_Apps_PhoneCall.ps1",
    "0088_002_Disable_device_access_for_Universal_Apps_Microphone.ps1",
    "0088_003_Disable_device_access_for_Universal_Apps_Contacts.ps1",
    "0088_004_Disable_device_access_for_Universal_Apps_CallHistory.ps1",
    "0088_005_Disable_device_access_for_Universal_Apps_Email.ps1",
    "0088_006_Disable_device_access_for_Universal_Apps_Messaging.ps1",
    "0088_007_Disable_device_access_for_Universal_Apps_Radios.ps1",
    "0088_008_Disable_device_access_for_Universal_Apps_Location.ps1",
    "0088_009_Disable_device_access_for_Universal_Apps_AccountInfo.ps1",
    "0088_010_Disable_device_access_for_Universal_Apps_Calendar.ps1",
    "0088_011_Disable_device_access_for_Universal_Apps_LocationService.ps1",
    "0088_012_Disable_device_access_for_Universal_Apps_LegacyDeviceAccess.ps1",
    "0088_013_Disable_device_access_for_Universal_Apps_Notifications.ps1",
    "0088_014_Disable_device_access_for_Universal_Apps_ActivityMeter.ps1",
    "0088_015_Disable_device_access_for_Universal_Apps_ActivitySensor.ps1",
    "0088_016_Disable_device_access_for_Universal_Apps_Tasks.ps1",
    "0088_017_Disable_device_access_for_Universal_Apps_3DViewer.ps1",
    "0162_Allow_global_apps_use_your_camera.bat",
    "0163_Deny_apps_read_or_send_messages.bat",
    "0168_Disable_Edge_password_manager.bat",
    "0171_Disable_mixed_reality_portal_holographics.bat",
    "0179_remove-contact-support-and-windows-feedback-packages-from-windows-10.ps1",
    "0180_Disable_submission_of_user_activities_into_the_cloud_UploadUserActivities.bat",
    "0216_Deny_apps_sync_LooselyCoupled.bat",
    "0225_Enable_Windows-Defender-ApplicationGuard.ps1",
    "0294_Prevent_Live_Tile_collection_MS_Edge.bat",
    "0295_Disable_MFU_Tracking_MS_Edge.bat",
    "0296_Disable_Recent_apps_MS_Edge.bat",
    "0297_Disable_Backstack_MS_Edge.bat",
    "0298_Configure_Windows_Defender_SmartScreen.bat",
    "0312_Enable_EMET_deephooks.bat",
    "0313_Enable_EMET_AntiDetours.bat",
    "0314_Enable_EMET_BannedFunctions.bat",
    "0315_Enable_EMET_ExploitAction.bat",
    "0327_Get_patches_updates.bat",
    "0411_Disable_allow_cortana_aboveLock.ps1"
)

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

foreach ($name in $archivedNames) {
    Assert-Test (Test-Path -LiteralPath (Join-Path $root "security\deprecated\$name") -PathType Leaf) "Archive missing: $name."
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $root "security\default\$name"))) "Obsolete script remains in default: $name."
}

foreach ($name in @(
    "0036_Disable_cortana_registry.ps1",
    "0036.03_Disable_cortana_registry_AllowSearchToUseLocation.ps1",
    "0056_Disable_with_policy_apprivacy.ps1",
    "0075_Disassembler0_Win10-Initial-Setup-Script.ps1",
    "0148_Disable_Cortana_AllowCloudSearch.bat",
    "0167_Enable_Notififications_Internet_explorer_SafeForScripting.bat",
    "0181_WynisWIN10-CISv1.0.ps1",
    "0205_Configure_CIS_Windows10_V181_DSC_hardening.ps1",
    "0342_windows-11-hardening-script.bat",
    "harden_windows10.bat"
)) {
    Assert-Test (Test-Path -LiteralPath (Join-Path $root "security\default\$name") -PathType Leaf) "Mixed or still-applicable script was moved: $name."
}

$profile = Get-Content (Join-Path $root "profilw11.ps1") -Raw
Assert-Test ($profile -notmatch '0036\.0[12]|0077_Disable_Microsoft_Windows_Maps') "Windows 11 profile still calls archived controls."

$report = [IO.File]::ReadAllLines((Join-Path $root "security\default\471.md"))
$controls = @($report | Where-Object { $_ -match '^\d+\.\s' })
Assert-Test ($controls.Count -eq 50) "Expected exactly 50 prioritized technical controls."
for ($i = 0; $i -lt $controls.Count; $i++) {
    Assert-Test ($controls[$i].StartsWith(($i + 1).ToString() + ". ")) "Report priority numbering is not sequential."
    Assert-Test ($controls[$i].Contains('`') -and $controls[$i] -match 'https://(learn\.microsoft\.com|github\.com/Raphire/Win11Debloat)/') "Control lacks technical identifier or source."
}

$identities = @($controls | ForEach-Object {
    Assert-Test ($_ -match '`([^`]+)`') "Control lacks an identity."
    $Matches[1]
})
Assert-Test (@($identities | Select-Object -Unique).Count -eq 50) "Report repeats a technical control identity."
Assert-Test (($controls -join "`n") -notmatch 'TurnOffWindowsCopilot|PreventDeviceEncryption|TurnOffSavingSnapshots') "Report includes obsolete or security-reducing upstream suggestions."

Write-Host "[PASS] All 39 archived scripts are in deprecated; mixed and still-applicable scripts remain."
Write-Host "[PASS] Windows 11 profile no longer calls the archived controls."
Write-Host "[PASS] Report contains 50 distinct, sequential, sourced technical controls."
