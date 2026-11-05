<#
.SYNOPSIS
  Audits VS Code telemetry settings and scans a project directory for
  suspicious tracking/telemetry scripts.

.EXAMPLE
  .\Audit-VSCodeTelemetry.ps1

.EXAMPLE
  .\Audit-VSCodeTelemetry.ps1 -ScanPath C:\src\project -IncludeExtensions
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ScanPath = (Get-Location).Path,

    [Parameter()]
    [switch]$IncludeExtensions,

    [Parameter()]
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$results = [ordered]@{
    Timestamp         = (Get-Date).ToString("o")
    ComputerName      = $env:COMPUTERNAME
    ScanPath          = (Resolve-Path -LiteralPath $ScanPath).Path
    Checks            = @()
    Findings          = @()
    Summary           = [ordered]@{
        Pass    = 0
        Warning = 0
        Fail    = 0
        Risk    = "Unknown"
    }
}

function Add-Check {
    param(
        [ValidateSet('PASS', 'WARNING', 'FAIL')]
        [string]$Status,
        [string]$Name,
        [string]$Detail,
        [string]$Path = ""
    )

    $results.Checks += [pscustomobject]@{
        Status = $Status
        Name   = $Name
        Detail = $Detail
        Path   = $Path
    }

    switch ($Status) {
        'PASS'    { $results.Summary.Pass++ }
        'WARNING' { $results.Summary.Warning++ }
        'FAIL'    { $results.Summary.Fail++ }
    }
}

function Add-Finding {
    param(
        [ValidateSet('Info', 'Low', 'Medium', 'High')]
        [string]$Severity,
        [string]$Category,
        [string]$Path,
        [string]$Detail
    )

    $results.Findings += [pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Path     = $Path
        Detail   = $Detail
    }
}

function Read-JsonFile {
    param([string]$Path)

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        return $raw | ConvertFrom-Json -AsHashtable
    }
    catch {
        Add-Check -Status 'WARNING' -Name 'Settings JSON parsing' `
            -Detail "Could not parse JSON: $($_.Exception.Message)" -Path $Path
        return $null
    }
}

function Get-SettingValue {
    param(
        [hashtable]$Settings,
        [string]$Key
    )

    if ($null -ne $Settings -and $Settings.ContainsKey($Key)) {
        return $Settings[$Key]
    }

    return $null
}

function Test-VSCodeSettings {
    param(
        [string]$Path,
        [string]$Scope
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check -Status 'WARNING' -Name "$Scope settings" `
            -Detail "settings.json was not found; this scope cannot be verified." -Path $Path
        return
    }

    $settings = Read-JsonFile -Path $Path
    if ($null -eq $settings) {
        return
    }

    $telemetryLevel = Get-SettingValue -Settings $settings -Key 'telemetry.telemetryLevel'

    if ($telemetryLevel -eq 'off') {
        Add-Check -Status 'PASS' -Name "$Scope telemetry level" `
            -Detail 'telemetry.telemetryLevel is set to off.' -Path $Path
    }
    elseif ($null -eq $telemetryLevel) {
        Add-Check -Status 'WARNING' -Name "$Scope telemetry level" `
            -Detail 'telemetry.telemetryLevel is absent; effective configuration cannot be proven disabled.' -Path $Path
    }
    else {
        Add-Check -Status 'FAIL' -Name "$Scope telemetry level" `
            -Detail "telemetry.telemetryLevel is '$telemetryLevel', not 'off'." -Path $Path
    }

    $legacyTelemetry = Get-SettingValue -Settings $settings -Key 'telemetry.enableTelemetry'
    if ($null -ne $legacyTelemetry) {
        if ($legacyTelemetry -eq $false) {
            Add-Check -Status 'PASS' -Name "$Scope legacy telemetry setting" `
                -Detail 'telemetry.enableTelemetry is false.' -Path $Path
        }
        else {
            Add-Check -Status 'FAIL' -Name "$Scope legacy telemetry setting" `
                -Detail "telemetry.enableTelemetry is '$legacyTelemetry'." -Path $Path
        }
    }

    $crashReporter = Get-SettingValue -Settings $settings -Key 'telemetry.enableCrashReporter'
    if ($null -ne $crashReporter) {
        if ($crashReporter -eq $false) {
            Add-Check -Status 'PASS' -Name "$Scope crash reporter setting" `
                -Detail 'telemetry.enableCrashReporter is false.' -Path $Path
        }
        else {
            Add-Check -Status 'FAIL' -Name "$Scope crash reporter setting" `
                -Detail "telemetry.enableCrashReporter is '$crashReporter'." -Path $Path
        }
    }
}

function Get-VSCodeUserSettingsPaths {
    $paths = New-Object System.Collections.Generic.List[object]

    if ($IsWindows) {
        $paths.Add([pscustomobject]@{
            Scope = 'User'
            Path  = (Join-Path $env:APPDATA 'Code\User\settings.json')
        })
        $paths.Add([pscustomobject]@{
            Scope = 'Insiders User'
            Path  = (Join-Path $env:APPDATA 'Code - Insiders\User\settings.json')
        })
    }
    elseif ($IsMacOS) {
        $paths.Add([pscustomobject]@{
            Scope = 'User'
            Path  = (Join-Path $HOME 'Library/Application Support/Code/User/settings.json')
        })
        $paths.Add([pscustomobject]@{
            Scope = 'Insiders User'
            Path  = (Join-Path $HOME 'Library/Application Support/Code - Insiders/User/settings.json')
        })
    }
    else {
        $paths.Add([pscustomobject]@{
            Scope = 'User'
            Path  = (Join-Path $HOME '.config/Code/User/settings.json')
        })
        $paths.Add([pscustomobject]@{
            Scope = 'Insiders User'
            Path  = (Join-Path $HOME '.config/Code - Insiders/User/settings.json')
        })
    }

    return $paths
}

function Test-SuspiciousFiles {
    param([string]$Root)

    $explicitRelativePaths = @(
        '.agents/hooks/scripts/track-telemetry.ps1',
        '.agents/hooks/scripts/track-telemetry.sh',
        '.agents/hooks/scripts/track-telemetry.py'
    )

    foreach ($relativePath in $explicitRelativePaths) {
        $candidate = Join-Path $Root $relativePath
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Add-Finding -Severity 'High' -Category 'Explicit tracking-script indicator' `
                -Path $candidate `
                -Detail "Matched a known tracking-script path: $relativePath"
        }
    }

    $scriptExtensions = @('.ps1', '.psm1', '.psd1', '.sh', '.bash', '.zsh', '.py', '.js', '.ts', '.cmd', '.bat')
    $namePattern = '(?i)(telemetry|tracking|analytics|metrics|beacon|fingerprint|instrumentation|exfil|webhook)'

    $files = Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $scriptExtensions -contains $_.Extension.ToLowerInvariant() -or
            $_.Name -match $namePattern
        }

    foreach ($file in $files) {
        $isExplicit = $file.FullName -match '(?i)[\\/]\.agents[\\/]hooks[\\/]scripts[\\/]track-telemetry\.(ps1|sh|py)$'
        if ($isExplicit) {
            continue
        }

        if ($file.Name -match $namePattern) {
            Add-Finding -Severity 'Medium' -Category 'Suspicious filename' `
                -Path $file.FullName `
                -Detail "Filename matches tracking-related keywords: $($file.Name)"
        }

        if ($file.Extension.ToLowerInvariant() -in $scriptExtensions) {
            try {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop

                $indicators = @(
                    'Application Insights',
                    'instrumentationKey',
                    'trackEvent',
                    'trackMetric',
                    'trackException',
                    'sendBeacon',
                    'google-analytics',
                    'googletagmanager',
                    'segment.com',
                    'mixpanel',
                    'posthog',
                    'amplitude',
                    'telemetry',
                    'analytics',
                    'Invoke-WebRequest',
                    'Invoke-RestMethod',
                    'curl ',
                    'wget '
                )

                $matched = $indicators | Where-Object { $content -match [regex]::Escape($_) }
                if ($matched.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Category 'Tracking/network indicator in script' `
                        -Path $file.FullName `
                        -Detail ("Matched indicators: " + ($matched -join ', '))
                }
            }
            catch {
                Add-Finding -Severity 'Low' -Category 'Unreadable candidate script' `
                    -Path $file.FullName `
                    -Detail "Could not inspect file contents: $($_.Exception.Message)"
            }
        }
    }
}

function Test-WorkspaceSettings {
    param([string]$Root)

    $workspaceSettings = Join-Path $Root '.vscode/settings.json'
    Test-VSCodeSettings -Path $workspaceSettings -Scope 'Workspace'
}

function Test-ExtensionTelemetry {
    if (-not $IncludeExtensions) {
        return
    }

    $extensionsRoot = if ($IsWindows) {
        Join-Path $env:USERPROFILE '.vscode\extensions'
    }
    else {
        Join-Path $HOME '.vscode/extensions'
    }

    if (-not (Test-Path -LiteralPath $extensionsRoot)) {
        Add-Check -Status 'WARNING' -Name 'Extension telemetry scan' `
            -Detail 'VS Code extension directory was not found.' -Path $extensionsRoot
        return
    }

    $packageFiles = Get-ChildItem -LiteralPath $extensionsRoot -Filter 'package.json' -File -Recurse -ErrorAction SilentlyContinue
    foreach ($packageFile in $packageFiles) {
        try {
            $package = Read-JsonFile -Path $packageFile.FullName
            if ($null -eq $package) {
                continue
            }

            $text = Get-Content -LiteralPath $packageFile.FullName -Raw -Encoding UTF8
            if ($text -match '(?i)(telemetry|applicationinsights|analytics|posthog|mixpanel|amplitude)') {
                Add-Finding -Severity 'Low' -Category 'Extension telemetry-related metadata' `
                    -Path $packageFile.FullName `
                    -Detail "Extension '$($package.name)' contains telemetry/analytics-related metadata."
            }
        }
        catch {
            Add-Finding -Severity 'Low' -Category 'Unreadable extension manifest' `
                -Path $packageFile.FullName `
                -Detail $_.Exception.Message
        }
    }
}

# User-level and Insiders settings
Get-VSCodeUserSettingsPaths | ForEach-Object {
    Test-VSCodeSettings -Path $_.Path -Scope $_.Scope
}

# Workspace configuration
Test-WorkspaceSettings -Root $results.ScanPath

# Project-local script scan
Test-SuspiciousFiles -Root $results.ScanPath

# Optional extension metadata scan
Test-ExtensionTelemetry

if ($results.Summary.Fail -gt 0 -or
    ($results.Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) {
    $results.Summary.Risk = 'High'
}
elseif ($results.Summary.Warning -gt 0 -or
        ($results.Findings | Where-Object { $_.Severity -in @('Medium', 'Low') }).Count -gt 0) {
    $results.Summary.Risk = 'Medium'
}
else {
    $results.Summary.Risk = 'Low'
}

if ($Json) {
    $results | ConvertTo-Json -Depth 8
    exit
}

Write-Host "`n=== VS Code Telemetry Audit ===" -ForegroundColor Cyan
Write-Host "Scan path: $($results.ScanPath)"
Write-Host "Risk level: $($results.Summary.Risk)`n" -ForegroundColor $(
    switch ($results.Summary.Risk) {
        'High'   { 'Red' }
        'Medium' { 'Yellow' }
        default  { 'Green' }
    }
)

$results.Checks | Format-Table Status, Name, Detail, Path -AutoSize

if ($results.Findings.Count -gt 0) {
    Write-Host "`n=== Non-standard / Suspicious Files ===" -ForegroundColor Yellow
    $results.Findings | Format-Table Severity, Category, Path, Detail -AutoSize
}
else {
    Write-Host "`nNo suspicious local tracking or telemetry scripts were identified." -ForegroundColor Green
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results.Summary.GetEnumerator() | Format-Table Name, Value -AutoSize

if ($results.Summary.Risk -eq 'High') {
    exit 2
}
elseif ($results.Summary.Risk -eq 'Medium') {
    exit 1
}
else {
    exit 0
}