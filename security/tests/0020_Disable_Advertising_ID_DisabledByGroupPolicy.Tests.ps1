$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0020_Disable_Advertising_ID_DisabledByGroupPolicy.ps1"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-AdvertisingIDScript {
    param([hashtable]$State)

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $ErrorAction -eq "Stop") "Unexpected path check."
        return $State.KeyExists
    }

    function New-Item {
        param($Path, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $Force -and $ErrorAction -eq "Stop") "Unexpected key creation options."
        $State.Creates++
        if ($State.Failure -eq "Create") { throw "Registry Create denied." }
        $State.KeyExists = $true
        return [pscustomobject]@{ Path = $Path }
    }

    function Get-ItemProperty {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $State.KeyExists -and $ErrorAction -eq "Stop") "Unexpected registry read."
        $State.Reads++
        if ($State.Failure -eq "Read") { throw "Registry Read denied." }
        return $State.Properties
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $Name -eq "DisabledByGroupPolicy") "Unexpected write target."
        Assert-Test ($Value -eq 1 -and $Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($case in @(
    @{ Name = "Missing key"; KeyExists = $false; Properties = [pscustomobject]@{}; Creates = 1; Reads = 1; Writes = 1 },
    @{ Name = "Missing value"; KeyExists = $true; Properties = [pscustomobject]@{ OtherPolicy = 1 }; Creates = 0; Reads = 1; Writes = 1 },
    @{ Name = "Value zero"; KeyExists = $true; Properties = [pscustomobject]@{ DisabledByGroupPolicy = 0 }; Creates = 0; Reads = 1; Writes = 1 },
    @{ Name = "Already configured"; KeyExists = $true; Properties = [pscustomobject]@{ DisabledByGroupPolicy = 1 }; Creates = 0; Reads = 1; Writes = 0 },
    @{ Name = "Creation failure"; KeyExists = $false; Properties = [pscustomobject]@{}; Creates = 1; Reads = 0; Writes = 0; Failure = "Create" },
    @{ Name = "Read failure"; KeyExists = $true; Properties = [pscustomobject]@{}; Creates = 0; Reads = 1; Writes = 0; Failure = "Read" },
    @{ Name = "Write failure"; KeyExists = $true; Properties = [pscustomobject]@{}; Creates = 0; Reads = 1; Writes = 1; Failure = "Write" }
)) {
    $state = @{
        KeyExists = $case.KeyExists
        Properties = $case.Properties
        Failure = $case.Failure
        Creates = 0
        Reads = 0
        Writes = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try {
        $result = @(Invoke-AdvertisingIDScript -State $state)
        Assert-Test ($result.Count -eq 0) "Unexpected pipeline output."
    }
    catch {
        $failure = $_.Exception.Message
    }
    $expectedError = if ($case.Failure) { "Registry $($case.Failure) denied." } else { $null }
    Assert-Test ($failure -eq $expectedError) "$($case.Name): unexpected error '$failure'."
    foreach ($counter in @("Creates", "Reads", "Writes")) {
        Assert-Test ($state[$counter] -eq $case[$counter]) "$($case.Name): unexpected $counter count."
    }
    $output = $state.Messages -join "`n"
    if ($case.Failure) {
        Assert-Test (-not $output.Contains("was set to 1") -and -not $output.Contains("[no change]")) "$($case.Name): failure reported success."
    }
    elseif ($case.Writes -eq 1) {
        Assert-Test ($output.Contains("was set to 1")) "$($case.Name): missing success message."
        if ($case.Creates -eq 1) {
            Assert-Test ($output.Contains("path does not exist. Creating it")) "$($case.Name): missing key creation message."
        }
    }
    else {
        Assert-Test ($output.Contains("[no change]")) "$($case.Name): missing no-change message."
    }
    Write-Host "[PASS] $($case.Name)."
}
