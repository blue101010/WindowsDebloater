$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0019_Disable_Steps_Recorder.ps1"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-StepsRecorderScript {
    param([hashtable]$State)

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $ErrorAction -eq "Stop") "Unexpected registry path check."
        return $State.KeyExists
    }

    function Get-ItemProperty {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $ErrorAction -eq "Stop") "Unexpected registry read."
        $State.Reads++
        if ($State.ReadError) {
            throw "Registry read denied."
        }
        return $State.Properties
    }

    function Get-ItemPropertyValue {
        throw "A missing registry value must not be read with Get-ItemPropertyValue."
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $Name -eq "DisableUAR") "Unexpected registry write target."
        Assert-Test ($Value -eq 1 -and $Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected registry write options."
        $State.Writes++
        if ($State.WriteError) {
            throw "Registry write denied."
        }
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($case in @(
    @{ Name = "Missing value"; KeyExists = $true; Properties = [pscustomobject]@{ OtherPolicy = 1 }; Writes = 1; Message = "does not exist in the registry" },
    @{ Name = "Disabled policy"; KeyExists = $true; Properties = [pscustomobject]@{ DisableUAR = 0 }; Writes = 1; Message = "Initial value of DisableUAR: 0" },
    @{ Name = "Already configured"; KeyExists = $true; Properties = [pscustomobject]@{ DisableUAR = 1 }; Writes = 0; Message = "already set to 1 [no change]" },
    @{ Name = "Missing key"; KeyExists = $false; Properties = $null; Writes = 0; Message = "does not exist. Exiting" },
    @{ Name = "Read failure"; KeyExists = $true; Properties = $null; Writes = 0; ReadError = $true; Error = "Registry read denied." },
    @{ Name = "Write failure"; KeyExists = $true; Properties = [pscustomobject]@{}; Writes = 1; WriteError = $true; Error = "Registry write denied." }
)) {
    $state = @{
        KeyExists = $case.KeyExists
        Properties = $case.Properties
        ReadError = $case.ReadError
        WriteError = $case.WriteError
        Reads = 0
        Writes = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try {
        Invoke-StepsRecorderScript -State $state
    }
    catch {
        $failure = $_.Exception.Message
    }
    Assert-Test ($failure -eq $case.Error) "$($case.Name): unexpected error '$failure'."
    Assert-Test ($state.Writes -eq $case.Writes) "$($case.Name): unexpected write count."
    $expectedReads = if ($case.KeyExists) { 1 } else { 0 }
    Assert-Test ($state.Reads -eq $expectedReads) "$($case.Name): unexpected read count."
    $output = $state.Messages -join "`n"
    if ($case.Message) {
        Assert-Test ($output.Contains($case.Message)) "$($case.Name): missing status message."
    }
    if ($case.Error) {
        Assert-Test (-not $output.Contains("was set to 1.")) "$($case.Name): failure reported success."
    }
    elseif ($case.Writes -eq 1) {
        Assert-Test ($output.Contains("DisableUAR was set to 1.")) "$($case.Name): missing success message."
    }
    Write-Host "[PASS] $($case.Name)."
}
