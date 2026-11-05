$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0025_Disable_Advertising_ID_for_Relevant_Ads_Enabled.ps1"
$expectedPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-AdvertisingStatusScript {
    param([hashtable]$State)

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $ErrorAction -eq "Stop") "Unexpected path check."
        return $State.KeyExists
    }

    function Get-ItemProperty {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $ErrorAction -eq "Stop") "Unexpected read."
        if ($State.Failure -eq "Read") { throw "Registry read denied." }
        return [pscustomobject]$State.Properties
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "Enabled") "Unexpected write target."
        Assert-Test ($Value -eq 0 -and $Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry write denied." }
        if ($State.Failure -ne "Mismatch") { $State.Properties.Enabled = $Value }
    }

    function Get-ItemPropertyValue {
        param($Path, $Name, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "Enabled" -and $ErrorAction -eq "Stop") "Unexpected verification read."
        $State.Verifications++
        if ($State.Failure -eq "Verify") { throw "Registry verification read denied." }
        return $State.Properties.Enabled
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    function Write-Warning {
        param([string]$Message)
        [void]$State.Warnings.Add($Message)
    }

    & $scriptPath
}

foreach ($case in @(
    @{ Name = "Enabled"; KeyExists = $true; Properties = @{ Enabled = 1 }; Writes = 1; Verifications = 1; Status = "[changed]" },
    @{ Name = "Missing value"; KeyExists = $true; Properties = @{}; Writes = 1; Verifications = 1; Status = "[changed]" },
    @{ Name = "Already disabled"; KeyExists = $true; Properties = @{ Enabled = 0 }; Writes = 0; Verifications = 1; Status = "[no change]" },
    @{ Name = "Missing key"; KeyExists = $false; Properties = @{}; Writes = 0; Verifications = 0 },
    @{ Name = "Read denied"; KeyExists = $true; Properties = @{}; Writes = 0; Verifications = 0; Failure = "Read"; Error = "Registry read denied." },
    @{ Name = "Write denied"; KeyExists = $true; Properties = @{ Enabled = 1 }; Writes = 1; Verifications = 0; Failure = "Write"; Error = "Registry write denied." },
    @{ Name = "Verification read denied"; KeyExists = $true; Properties = @{ Enabled = 1 }; Writes = 1; Verifications = 1; Failure = "Verify"; Error = "Registry verification read denied." },
    @{ Name = "Verification mismatch"; KeyExists = $true; Properties = @{ Enabled = 1 }; Writes = 1; Verifications = 1; Failure = "Mismatch"; Error = "*Verification failed:*" }
)) {
    $state = @{
        KeyExists = $case.KeyExists
        Properties = $case.Properties
        Failure = $case.Failure
        Writes = 0
        Verifications = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
        Warnings = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try { Invoke-AdvertisingStatusScript -State $state }
    catch { $failure = $_.Exception.Message }
    if ($case.Error) {
        Assert-Test ($failure -like $case.Error) "$($case.Name): unexpected error '$failure'."
    }
    else {
        Assert-Test ($null -eq $failure) "$($case.Name): unexpected error '$failure'."
    }
    Assert-Test ($state.Writes -eq $case.Writes -and $state.Verifications -eq $case.Verifications) "$($case.Name): unexpected operation counts."
    $output = $state.Messages -join "`n"
    if ($case.Status) {
        Assert-Test ($output.Contains("[confirmed]") -and $output.Contains($case.Status) -and $output.Contains("Enabled = 0 (disabled)")) "$($case.Name): missing confirmed status."
    }
    else {
        Assert-Test ($state.Messages.Count -eq 0) "$($case.Name): incorrectly reported success."
        if (-not $case.KeyExists) {
            Assert-Test ($state.Warnings.Count -eq 1 -and $state.Warnings[0].Contains("Status not confirmed")) "Missing key did not warn."
        }
    }
    Write-Host "[PASS] $($case.Name)."
}
