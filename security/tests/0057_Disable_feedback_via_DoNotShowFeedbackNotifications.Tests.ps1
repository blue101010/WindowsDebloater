$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0057_Disable_feedback_via_DoNotShowFeedbackNotifications.ps1"
$expectedPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$expectedName = "DoNotShowFeedbackNotifications"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-FeedbackScript {
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
        param($Path, $Name, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $State.KeyExists -and $ErrorAction -eq "Stop" -and -not $Name) "Read must not require a missing value."
        if ($State.Failure -eq "Read") { throw "Registry Read denied." }
        return [pscustomobject]$State.Properties
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq $expectedName -and $Value -eq 1) "Unexpected write target or value."
        Assert-Test ($Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        $State.Properties[$Name] = $Value
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($scenario in @("Missing key", "Missing value", "Value zero", "Already configured", "Create", "Read", "Write")) {
    $state = @{
        KeyExists = $scenario -notin @("Missing key", "Create")
        Properties = @{ OtherPolicy = 3 }
        Creates = 0
        Writes = 0
        Failure = $scenario
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    if ($scenario -eq "Value zero") { $state.Properties[$expectedName] = 0 }
    if ($scenario -eq "Already configured") { $state.Properties[$expectedName] = 1 }
    $failure = $null
    try {
        $output = @(Invoke-FeedbackScript -State $state)
        Assert-Test ($output.Count -eq 0) "Unexpected pipeline output."
    }
    catch { $failure = $_.Exception.Message }
    $messages = $state.Messages -join "`n"
    if ($scenario -in @("Create", "Read", "Write")) {
        Assert-Test ($failure -eq "Registry $scenario denied.") "$scenario error was not propagated: $failure"
        Assert-Test ($messages -notmatch "has been updated|is already set") "$scenario failure reported success."
        Assert-Test ($state.Writes -eq $(if ($scenario -eq "Write") { 1 } else { 0 })) "$scenario did not stop subsequent writes."
    }
    else {
        Assert-Test ($null -eq $failure) "$scenario failed: $failure"
        Assert-Test ($state.Properties[$expectedName] -eq 1 -and $state.Properties.OtherPolicy -eq 3) "$scenario left incorrect registry values."
        Assert-Test ($state.Creates -eq $(if ($scenario -eq "Missing key") { 1 } else { 0 })) "$scenario created unexpected keys."
        Assert-Test ($state.Writes -eq $(if ($scenario -eq "Already configured") { 0 } else { 1 })) "$scenario performed unexpected writes."
        $expectedStatus = if ($scenario -eq "Already configured") { "is already set to 1" } else { "has been updated to 1" }
        Assert-Test ($messages.Contains($expectedStatus)) "$scenario omitted status."
        $state.Creates = 0
        $state.Writes = 0
        $state.Messages.Clear()
        Invoke-FeedbackScript -State $state
        Assert-Test ($state.Creates -eq 0 -and $state.Writes -eq 0) "$scenario repeat run modified the registry."
        Assert-Test (($state.Messages -join "`n").Contains("is already set to 1")) "$scenario repeat run omitted status."
    }
    Write-Host "[PASS] $scenario."
}
