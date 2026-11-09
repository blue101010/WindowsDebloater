$ErrorActionPreference = 'Stop'
$defaultDir = Join-Path $PSScriptRoot '..\default'
$source = Join-Path $defaultDir '0075_Disassembler0_Win10-Initial-Setup-Script.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {
    throw "0075 failed to parse: $($errors[0].Message)"
}

$functions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true) | ForEach-Object { $_.Name })
$removed = @('DisableSensors', 'DisableLocation', 'DisableStartupSound')
foreach ($name in $removed) {
    if ($functions -contains $name) {
        throw "Duplicate function remains in 0075: $name."
    }
}
foreach ($name in @('EnableSensors', 'EnableLocation', 'EnableStartupSound', 'DisableTelemetry', 'DisableOneDrive')) {
    if ($functions -notcontains $name) {
        throw "Expected function missing from 0075: $name."
    }
}

$commands = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst]
}, $true))
foreach ($command in $commands) {
    if ($removed -contains $command.GetCommandName()) {
        throw "0075 still calls removed function $($command.GetCommandName())."
    }
}

foreach ($file in @('0086_Disable_location_access_and_sensors.ps1', '0493_disable_windows_disableStatupSound.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $defaultDir $file) -PathType Leaf)) {
        throw "Standalone replacement missing: $file."
    }
}

Write-Host '[PASS] Duplicate functions removed; inverse and partially covered functions retained.'
