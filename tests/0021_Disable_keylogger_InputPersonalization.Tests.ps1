$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0021_Disable_keylogger_InputPersonalization.ps1"
$targets = @(
    @{ Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"; Name = "HarvestContacts"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
    @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
    @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "AllowInputPersonalization"; Value = 0 }
)

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-InputPersonalizationScript {
    param([hashtable]$State)

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($ErrorAction -eq "Stop") "Path check must stop on errors."
        Assert-Test ($Path -in $targets.Path) "Unexpected registry path."
        return $State.Keys.ContainsKey($Path)
    }

    function New-Item {
        param($Path, [switch]$Force, $ErrorAction)
        Assert-Test ($Force -and $ErrorAction -eq "Stop") "Unexpected creation options."
        $State.Creates++
        if ($State.Failure -eq "Create") { throw "Registry Create denied." }
        $State.Keys[$Path] = @{}
        return [pscustomobject]@{ Path = $Path }
    }

    function Get-ItemProperty {
        param($Path, $ErrorAction)
        Assert-Test ($State.Keys.ContainsKey($Path) -and $ErrorAction -eq "Stop") "Unexpected registry read."
        if ($State.Failure -eq "Read") { throw "Registry Read denied." }
        return [pscustomobject]$State.Keys[$Path]
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        $target = @($targets | Where-Object { $_.Path -eq $Path -and $_.Name -eq $Name })
        Assert-Test ($target.Count -eq 1 -and $Value -eq $target[0].Value) "Unexpected registry write."
        Assert-Test ($Value -is [int] -and $Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        $State.Keys[$Path][$Name] = $Value
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($scenario in @("Missing keys", "Missing values", "Incorrect values", "Already configured", "Create", "Read", "Write")) {
    $state = @{
        Keys = @{}
        Creates = 0
        Writes = 0
        Failure = $scenario
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    if ($scenario -notin @("Missing keys", "Create")) {
        foreach ($target in $targets) {
            if (-not $state.Keys.ContainsKey($target.Path)) { $state.Keys[$target.Path] = @{} }
            if ($scenario -eq "Already configured") { $state.Keys[$target.Path][$target.Name] = $target.Value }
            if ($scenario -eq "Incorrect values") { $state.Keys[$target.Path][$target.Name] = 1 - $target.Value }
        }
    }
    $failure = $null
    try { Invoke-InputPersonalizationScript -State $state }
    catch { $failure = $_.Exception.Message }
    $output = $state.Messages -join "`n"
    if ($scenario -in @("Create", "Read", "Write")) {
        Assert-Test ($failure -eq "Registry $scenario denied.") "$scenario failure was not propagated: $failure"
        Assert-Test (-not $output.Contains("Value changed") -and -not $output.Contains("No change")) "$scenario failure reported success."
        Assert-Test ($state.Writes -eq $(if ($scenario -eq "Write") { 1 } else { 0 })) "$scenario failure did not stop subsequent writes."
    }
    else {
        Assert-Test ($null -eq $failure) "$scenario failed: $failure"
        $expectedCreates = if ($scenario -eq "Missing keys") { @($targets.Path | Select-Object -Unique).Count } else { 0 }
        Assert-Test ($state.Creates -eq $expectedCreates) "$scenario created an unexpected number of keys."
        $expectedWrites = if ($scenario -eq "Already configured") { 0 } else { $targets.Count }
        Assert-Test ($state.Writes -eq $expectedWrites) "$scenario wrote an unexpected number of values."
        foreach ($target in $targets) {
            Assert-Test ($state.Keys[$target.Path][$target.Name] -eq $target.Value) "$scenario left an incorrect value for $($target.Name)."
        }
        $state.Writes = 0
        $state.Creates = 0
        $state.Messages.Clear()
        Invoke-InputPersonalizationScript -State $state
        Assert-Test ($state.Writes -eq 0 -and $state.Creates -eq 0) "$scenario repeat run was not idempotent."
        Assert-Test (@($state.Messages | Where-Object { $_.Contains("No change") }).Count -eq $targets.Count) "$scenario repeat run did not report all unchanged values."
    }
    Write-Host "[PASS] $scenario."
}
