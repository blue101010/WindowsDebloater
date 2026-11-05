$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0394_Disable_Brave_AutofillAddressEnabled.ps1"
$expectedPath = "HKCU:\Software\Policies\BraveSoftware\Brave"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-AutofillScript {
    param([hashtable]$State)

    function Test-Path {
        param($LiteralPath, $ErrorAction)
        Assert-Test ($LiteralPath -eq $expectedPath -and $ErrorAction -eq "Stop") "Unexpected path check."
        return $State.Exists
    }

    function New-Item {
        param($Path, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Force -and $ErrorAction -eq "Stop") "Unexpected creation."
        $State.Creates++
        if ($State.Failure -eq "Create") { throw "Registry Create denied." }
        $State.Exists = $true
    }

    function Get-ItemProperty {
        param($Path, $Name, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $State.Exists -and -not $Name -and $ErrorAction -eq "Stop") "Unexpected read."
        if ($State.Failure -eq "Read") { throw "Registry Read denied." }
        return [pscustomobject]$State.Properties
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "AutofillAddressEnabled" -and $Value -eq 0) "Unexpected write."
        Assert-Test ($Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        if ($State.Failure -ne "Mismatch") { $State.Properties[$Name] = $Value }
    }

    function Get-ItemPropertyValue {
        param($Path, $Name, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "AutofillAddressEnabled" -and $ErrorAction -eq "Stop") "Unexpected verification."
        if ($State.Failure -eq "Verify") { throw "Registry Verify denied." }
        return $State.Properties[$Name]
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($scenario in @("Missing key", "Missing value", "Enabled", "Already disabled", "Create", "Read", "Write", "Verify", "Mismatch")) {
    $state = @{
        Exists = $scenario -notin @("Missing key", "Create")
        Properties = @{ OtherPolicy = 7 }
        Creates = 0
        Writes = 0
        Failure = $scenario
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    if ($scenario -eq "Already disabled") { $state.Properties.AutofillAddressEnabled = 0 }
    if ($scenario -in @("Enabled", "Mismatch")) { $state.Properties.AutofillAddressEnabled = 1 }
    $failure = $null
    try { $result = Invoke-AutofillScript -State $state }
    catch { $failure = $_.Exception.Message }
    $messages = $state.Messages -join "`n"
    if ($scenario -in @("Create", "Read", "Write", "Verify", "Mismatch")) {
        $pattern = if ($scenario -eq "Mismatch") { "*Verification failed:*" } else { "Registry $scenario denied." }
        Assert-Test ($failure -like $pattern -and -not $messages.Contains("[confirmed]")) "${scenario}: unexpected failure/status: $failure"
    }
    else {
        Assert-Test ($null -eq $failure -and $result.AutofillAddressEnabled -eq 0 -and $result.OtherPolicy -eq 7) "${scenario}: unexpected configuration: $failure"
        Assert-Test ($state.Creates -eq $(if ($scenario -eq "Missing key") { 1 } else { 0 })) "${scenario}: unexpected creations."
        Assert-Test ($state.Writes -eq $(if ($scenario -eq "Already disabled") { 0 } else { 1 })) "${scenario}: unexpected writes."
        Assert-Test ($messages.Contains("[confirmed]") -and $messages.Contains("AutofillAddressEnabled = 0 (disabled)")) "${scenario}: missing status."
        $state.Creates = 0
        $state.Writes = 0
        $null = Invoke-AutofillScript -State $state
        Assert-Test ($state.Creates -eq 0 -and $state.Writes -eq 0) "${scenario}: repeat run changed values."
    }
    Write-Host "[PASS] $scenario."
}
