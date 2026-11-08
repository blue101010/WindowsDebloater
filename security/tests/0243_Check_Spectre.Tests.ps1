$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0243_Check_Spectre.ps1"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-SpectreScript {
    param([hashtable]$State)

    function Get-Module {
        param([switch]$ListAvailable, $Name, $ErrorAction)
        Assert-Test ($ListAvailable -and $Name -eq "SpeculationControl" -and $ErrorAction -eq "Stop") "Unexpected module lookup."
        if ($State.Installed) { [pscustomobject]@{ Name = $Name } }
    }

    function Install-Module {
        param($Name, $Scope, $ErrorAction)
        Assert-Test ($Name -eq "SpeculationControl" -and $Scope -eq "CurrentUser" -and $ErrorAction -eq "Stop") "Unexpected installation options."
        $State.Installs++
        if ($State.Failure -eq "Install") { throw "Module installation failed." }
    }

    function Import-Module {
        param($Name, $ErrorAction)
        Assert-Test ($Name -eq "SpeculationControl" -and $ErrorAction -eq "Stop") "Unexpected import."
        $State.Imports++
        if ($State.Failure -eq "Import") { throw "Module import failed." }
    }

    function Get-SpeculationControlSettings {
        param($ErrorAction)
        Assert-Test ($ErrorAction -eq "Stop" -and $State.Imports -eq 1) "Settings invoked before import."
        $State.Checks++
        if ($State.Failure -eq "Check") { throw "Settings check failed." }
        return [pscustomobject]@{ TestResult = "Settings reported" }
    }

    & $scriptPath
}

foreach ($scenario in @("Installed", "Missing", "Install", "Import", "Check")) {
    $state = @{
        Installed = $scenario -notin @("Missing", "Install")
        Failure = $scenario
        Installs = 0
        Imports = 0
        Checks = 0
    }
    $failure = $null
    try { $result = Invoke-SpectreScript -State $state }
    catch { $failure = $_.Exception.Message }
    $expectedInstalls = if ($state.Installed) { 0 } else { 1 }
    $expectedImports = if ($scenario -eq "Install") { 0 } else { 1 }
    $expectedChecks = if ($scenario -in @("Install", "Import")) { 0 } else { 1 }
    Assert-Test ($state.Installs -eq $expectedInstalls -and $state.Imports -eq $expectedImports -and $state.Checks -eq $expectedChecks) "${scenario}: unexpected command counts."
    $expectedError = switch ($scenario) {
        "Install" { "Module installation failed." }
        "Import" { "Module import failed." }
        "Check" { "Settings check failed." }
        default { $null }
    }
    Assert-Test ($failure -eq $expectedError) "${scenario}: unexpected error '$failure'."
    if (-not $expectedError) {
        Assert-Test ($result.TestResult -eq "Settings reported") "${scenario}: missing settings output."
    }
    Write-Host "[PASS] $scenario."
}
