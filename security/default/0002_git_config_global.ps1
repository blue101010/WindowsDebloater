<#
.SYNOPSIS
Sets and verifies the global Git author name and email for the current user.

.DESCRIPTION
Requires Git on PATH. Reports success only after reading back each setting.
Exits with code 1 if Git is unavailable, a command fails, or verification fails.
#>

$title = "[0002_git_config_global]"
$settings = [ordered]@{
    "user.name" = "blue101010"
    "user.email" = "none@hello.com"
}

try {
    $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
}
catch {
    Write-Host "$title [FAIL] Git is unavailable. Install Git and ensure it is on PATH. $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$failed = $false
foreach ($setting in $settings.GetEnumerator()) {
    try {
        Write-Host "$title Setting global $($setting.Key)..."
        & $gitCommand.Source config --global --replace-all $setting.Key $setting.Value
        if ($LASTEXITCODE -ne 0) {
            throw "git config write failed with exit code $LASTEXITCODE."
        }

        $actual = @(& $gitCommand.Source config --global --get-all $setting.Key)
        if ($LASTEXITCODE -ne 0) {
            throw "git config read failed with exit code $LASTEXITCODE."
        }
        if ($actual.Count -ne 1 -or $actual[0] -cne $setting.Value) {
            throw "Verification failed: expected exactly one matching global value."
        }

        Write-Host "$title [SUCCESS] Global $($setting.Key) verified." -ForegroundColor Green
    }
    catch {
        $failed = $true
        Write-Host "$title [FAIL] Global $($setting.Key): $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($failed) {
    Write-Host "$title [FAIL] Global Git configuration did not complete successfully." -ForegroundColor Red
    exit 1
}

Write-Host "$title [SUCCESS] All global Git settings verified." -ForegroundColor Green
exit 0