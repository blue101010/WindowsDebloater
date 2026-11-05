$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0002_git_config_global.ps1"
$gitPath = (Get-Command git -CommandType Application -ErrorAction Stop).Source
$powerShellPath = (Get-Process -Id $PID).Path
$tempPath = Join-Path ([IO.Path]::GetTempPath()) ("git-config-tests-" + [guid]::NewGuid())
$configPath = Join-Path $tempPath "gitconfig"
$environmentNames = @("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT", "XDG_CONFIG_HOME", "PATH")
$savedEnvironment = @{}
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-ConfigScript {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powerShellPath
    $startInfo.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $stdout.Result + $stderr.Result
        }
    }
    finally {
        $process.Dispose()
    }
}

try {
    [void](New-Item -ItemType Directory -Path $tempPath)
    $env:GIT_CONFIG_GLOBAL = $configPath
    $env:GIT_CONFIG_NOSYSTEM = "1"
    $env:GIT_CONFIG_COUNT = "0"
    $env:XDG_CONFIG_HOME = $tempPath

    $result = Invoke-ConfigScript
    Assert-Test ($result.ExitCode -eq 0) "Initial configuration failed: $($result.Output)"
    foreach ($key in @("user.name", "user.email")) {
        $expected = if ($key -eq "user.name") { "blue101010" } else { "none@hello.com" }
        $actual = @(& $gitPath config --global --get-all $key)
        Assert-Test ($LASTEXITCODE -eq 0 -and $actual.Count -eq 1 -and $actual[0] -ceq $expected) "Incorrect $key."
        Assert-Test ($result.Output.Contains("[SUCCESS] Global $key verified.")) "Missing success status for $key."
    }
    Assert-Test (-not $result.Output.Contains("[FAIL]")) "Unexpected failure status."
    Write-Host "[PASS] Writes and verifies both settings."

    $result = Invoke-ConfigScript
    Assert-Test ($result.ExitCode -eq 0) "Repeat run failed: $($result.Output)"
    Write-Host "[PASS] Repeat execution succeeds."

    & $gitPath config --global --add user.name "duplicate"
    Assert-Test ($LASTEXITCODE -eq 0) "Could not prepare duplicate setting."
    $result = Invoke-ConfigScript
    $actual = @(& $gitPath config --global --get-all user.name)
    Assert-Test ($result.ExitCode -eq 0 -and $LASTEXITCODE -eq 0 -and $actual.Count -eq 1 -and $actual[0] -ceq "blue101010") "Duplicate replacement failed."
    Write-Host "[PASS] Duplicate values are replaced."

    # A directory cannot be used as a Git configuration file.
    $env:GIT_CONFIG_GLOBAL = $tempPath
    $result = Invoke-ConfigScript
    Assert-Test ($result.ExitCode -eq 1) "Write failure did not return exit code 1."
    foreach ($key in @("user.name", "user.email")) {
        Assert-Test ($result.Output.Contains("[FAIL] Global ${key}:")) "Missing failure status for $key."
    }
    Assert-Test (-not $result.Output.Contains("[SUCCESS]")) "Write failure reported success."
    Write-Host "[PASS] Write failures report failure and exit code 1."

    $env:GIT_CONFIG_GLOBAL = $configPath
    $env:PATH = ""
    $result = Invoke-ConfigScript
    Assert-Test ($result.ExitCode -eq 1 -and $result.Output.Contains("[FAIL] Git is unavailable.")) "Missing Git was not reported correctly."
    Assert-Test (-not $result.Output.Contains("[SUCCESS]")) "Missing Git reported success."
    Write-Host "[PASS] Missing Git reports failure and exit code 1."
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
    }
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        Remove-Item -LiteralPath $configPath -Force
    }
    if (Test-Path -LiteralPath $tempPath) {
        Remove-Item -LiteralPath $tempPath
    }
}
