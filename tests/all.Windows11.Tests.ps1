$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\all.bat"
$lines = [IO.File]::ReadAllLines($scriptPath)
$registryLines = @($lines | Where-Object { $_ -match '^\s*(?:::)?\s*reg\s+add\b' })
$commands = @($lines | Where-Object { $_ -match '^\s*\S' -and $_ -notmatch '^\s*(?:REM\b|::)' })

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

foreach ($obsolete in @(
    'LimitEnhancedDiagnosticDataWindowsAnalytics',
    'HidePeopleBar',
    '\\PCHealth\\',
    '/v "NoRDS"',
    'DisableSendGenericDriverNotFoundToWER',
    'DisableSendRequestAdditionalSoftwareToWER',
    '\\UEV\\Agent\\Configuration\\Windows8AppList\\',
    'ForceActiveDesktopOn',
    'NoActiveDesktop',
    '\\Policies\\ActiveDesktop',
    '\\Sidebar"',
    'NoInternetOpenWith',
    '\\GameUX"',
    '\\Windows\\Maps"',
    'DisableAntiSpyware'
)) {
    Assert-Test (@($registryLines | Where-Object { $_ -match $obsolete }).Count -eq 0) "Obsolete registry control remains: $obsolete."
}

Assert-Test (@($commands | Where-Object {
    $_ -match '^netsh .* (?:set|add) rule .*?(?:Cortana|OneNote)'
}).Count -eq 0) "Retired Cortana/OneNote UWP firewall target remains."

foreach ($retained in @(
    'PreventCDDVDMetadataRetrieval',
    'DisableRealtimeMonitoring',
    'DontSendAdditionalData',
    'NtpServer',
    'LetAppsAccessTasks',
    'AllowSpeechModelUpdate'
)) {
    Assert-Test (@($registryLines | Where-Object { $_ -match $retained }).Count -gt 0) "Retained control is missing: $retained."
}

foreach ($name in @("Cortana", "OneNote")) {
    foreach ($direction in @("in", "out")) {
        $cleanup = 'netsh advfirewall firewall delete rule name="block_' + $name + '_' + $direction + '"'
        Assert-Test ($commands -ccontains $cleanup) "Previous-run cleanup is missing: $cleanup."
    }
}

Assert-Test (@($commands | Where-Object { $_ -match '^reg add ' }).Count -eq 81) "Expected 81 active registry writes."
Assert-Test (@($registryLines | Where-Object { $_ -match '^:: reg add ' }).Count -eq 9) "Expected nine optional registry writes."
Assert-Test (@($commands | Where-Object { $_ -match '^schtasks ' }).Count -eq 11) "Scheduled-task commands changed."
Assert-Test ($commands -ccontains 'w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"') "NTP command changed."

Write-Host "[PASS] Confirmed obsolete registry and retired-app firewall targets are absent."
Write-Host "[PASS] Retained settings, scheduled tasks and legacy-rule cleanup remain."
Write-Host "[PASS] Static checks only; no registry, firewall or task changes were executed."
