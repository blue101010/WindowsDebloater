$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0055_Disable_windows_customer_experience_improvement_program_CorporateSQMURL.ps1"
$expectedPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-SQMClientScript {
    param([hashtable]$State)

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $ErrorAction -eq "Stop") "Unexpected path check."
        return $State.KeyExists
    }

    function New-Item {
        param($Path, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Force -and $ErrorAction -eq "Stop") "Unexpected key creation."
        $State.Creates++
        if ($State.Failure -eq "Create") { throw "Registry Create denied." }
        $State.KeyExists = $true
        return [pscustomobject]@{ Path = $Path }
    }

    function Get-ItemProperty {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $State.KeyExists -and $ErrorAction -eq "Stop") "Unexpected read."
        if ($State.Failure -eq "Read") { throw "Registry Read denied." }
        return [pscustomobject]$State.Properties
    }

    function New-ItemProperty {
        param($Path, $Name, $Value, $PropertyType, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "CorporateSQMURL" -and $Value -ceq "0.0.0.0") "Unexpected property creation."
        Assert-Test ($State.KeyExists -and $PropertyType -eq "String" -and $Force -and $ErrorAction -eq "Stop") "Unexpected creation options."
        $State.NewValues++
        if ($State.Failure -eq "NewValue") { throw "Registry NewValue denied." }
        $State.Properties.CorporateSQMURL = $Value
        return [pscustomobject]@{ CorporateSQMURL = $Value }
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "CorporateSQMURL" -and $Value -ceq "0.0.0.0") "Unexpected write."
        Assert-Test ($Type -eq "String" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        $State.Properties.CorporateSQMURL = $Value
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($scenario in @("Missing key", "Missing value", "Different value", "Already configured", "Create", "Read", "NewValue", "Write")) {
    $state = @{
        KeyExists = $scenario -notin @("Missing key", "Create")
        Properties = @{}
        Creates = 0
        NewValues = 0
        Writes = 0
        Failure = $scenario
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    if ($scenario -in @("Different value", "Write")) { $state.Properties.CorporateSQMURL = "previous-value" }
    if ($scenario -eq "Already configured") { $state.Properties.CorporateSQMURL = "0.0.0.0" }
    $failure = $null
    try {
        $output = @(Invoke-SQMClientScript -State $state)
        Assert-Test ($output.Count -eq 0) "Unexpected pipeline output."
    }
    catch { $failure = $_.Exception.Message }
    if ($scenario -in @("Create", "Read", "NewValue", "Write")) {
        Assert-Test ($failure -eq "Registry $scenario denied.") "$scenario error was not propagated: $failure"
        Assert-Test (($state.Messages -join "`n") -notmatch "created and set|adjusted to|No modification") "$scenario failure reported success."
    }
    else {
        Assert-Test ($null -eq $failure) "$scenario failed: $failure"
        Assert-Test ($state.Properties.CorporateSQMURL -ceq "0.0.0.0") "$scenario left an incorrect value."
        Assert-Test ($state.Creates -eq $(if ($scenario -eq "Missing key") { 1 } else { 0 })) "$scenario created unexpected keys."
        Assert-Test ($state.NewValues -eq $(if ($scenario -in @("Missing key", "Missing value")) { 1 } else { 0 })) "$scenario created unexpected values."
        Assert-Test ($state.Writes -eq $(if ($scenario -eq "Different value") { 1 } else { 0 })) "$scenario performed unexpected writes."
        $state.Creates = 0
        $state.NewValues = 0
        $state.Writes = 0
        $state.Messages.Clear()
        Invoke-SQMClientScript -State $state
        Assert-Test ($state.Creates -eq 0 -and $state.NewValues -eq 0 -and $state.Writes -eq 0) "$scenario repeat run modified the registry."
        Assert-Test (($state.Messages -join "`n").Contains("No modification")) "$scenario repeat run omitted status."
    }
    Write-Host "[PASS] $scenario."
}
