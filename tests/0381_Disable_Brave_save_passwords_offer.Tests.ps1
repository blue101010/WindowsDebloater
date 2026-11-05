$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0381_Disable_Brave_save_passwords_offer.ps1"
$tempPath = Join-Path ([IO.Path]::GetTempPath()) ("brave-password-test-" + [guid]::NewGuid())
$prefsDirectory = Join-Path $tempPath "BraveSoftware\Brave-Browser\User Data\Default"
$prefsPath = Join-Path $prefsDirectory "Preferences"
$savedLocalAppData = $env:LOCALAPPDATA

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

try {
    New-Item -ItemType Directory -Path $prefsDirectory -Force | Out-Null
    $env:LOCALAPPDATA = $tempPath
    foreach ($json in @(
        '{"profile":{"password_manager_enabled":true,"other":7},"unrelated":{"name":"keep"}}',
        '{"profile":{"password_manager_enabled":false,"other":7},"unrelated":{"name":"keep"}}',
        '{"profile":{"other":7},"unrelated":{"name":"keep"}}',
        '{"unrelated":{"name":"keep"}}'
    )) {
        Set-Content -LiteralPath $prefsPath -Value $json -Encoding UTF8
        & $scriptPath
        $result = Get-Content -LiteralPath $prefsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Test ($result.profile.password_manager_enabled -ceq $false) "Password preference not disabled."
        Assert-Test ($result.unrelated.name -eq "keep") "Unrelated data lost."
        if ($json.Contains('"other"')) {
            Assert-Test ($result.profile.other -eq 7) "Unrelated profile preference lost."
        }
        & $scriptPath
        Write-Host "[PASS] Configuration and repeat execution: $json"
    }
    Set-Content -LiteralPath $prefsPath -Value '{invalid json' -Encoding UTF8
    $before = Get-Content -LiteralPath $prefsPath -Raw
    $failure = $null
    try { & $scriptPath }
    catch { $failure = $_ }
    Assert-Test ($null -ne $failure -and (Get-Content -LiteralPath $prefsPath -Raw) -ceq $before) "Invalid JSON was not rejected without changing the file."
    Write-Host "[PASS] Invalid JSON stops execution without overwriting preferences."
}
finally {
    $env:LOCALAPPDATA = $savedLocalAppData
    if (Test-Path -LiteralPath $prefsPath) { Remove-Item -LiteralPath $prefsPath -Force }
    foreach ($directory in @($prefsDirectory, (Split-Path $prefsDirectory), (Join-Path $tempPath "BraveSoftware\Brave-Browser"), (Join-Path $tempPath "BraveSoftware"), $tempPath)) {
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory }
    }
}
