$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0036.01_Disable_cortana_registry_AllowCortana.ps1"
$expectedPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-CortanaScript {
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
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "AllowCortana" -and $Value -eq 0) "Unexpected property creation."
        Assert-Test ($State.KeyExists -and $PropertyType -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected creation options."
        $State.NewValues++
        if ($State.Failure -eq "NewValue") { throw "Registry NewValue denied." }
        $State.Properties.AllowCortana = $Value
        return [pscustomobject]@{ AllowCortana = $Value }
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $expectedPath -and $Name -eq "AllowCortana" -and $Value -eq 0) "Unexpected write."
        Assert-Test ($Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        $State.Properties.AllowCortana = $Value
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($scenario in @("Missing key", "Missing value", "Enabled", "Already disabled", "Create", "Read", "NewValue", "Write")) {
    $state = @{
        KeyExists = $scenario -notin @("Missing key", "Create")
        Properties = @{}
        Creates = 0
        NewValues = 0
        Writes = 0
        Failure = $scenario
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    if ($scenario -in @("Enabled", "Write")) { $state.Properties.AllowCortana = 1 }
    if ($scenario -eq "Already disabled") { $state.Properties.AllowCortana = 0 }
    $failure = $null
    try {
        $output = @(Invoke-CortanaScript -State $state)
        Assert-Test ($output.Count -eq 0) "Unexpected pipeline output."
    }
    catch { $failure = $_.Exception.Message }
    if ($scenario -in @("Create", "Read", "NewValue", "Write")) {
        Assert-Test ($failure -eq "Registry $scenario denied.") "$scenario error was not propagated: $failure"
        $messages = $state.Messages -join "`n"
        Assert-Test ($messages -notmatch "created and set|adjusted to|No modification") "$scenario failure reported success."
    }
    else {
        Assert-Test ($null -eq $failure) "$scenario failed: $failure"
        Assert-Test ($state.Properties.ContainsKey("AllowCortana") -and $state.Properties.AllowCortana -eq 0) "$scenario did not disable Cortana."
        Assert-Test ($state.Creates -eq $(if ($scenario -eq "Missing key") { 1 } else { 0 })) "$scenario created unexpected keys."
        Assert-Test ($state.NewValues -eq $(if ($scenario -in @("Missing key", "Missing value")) { 1 } else { 0 })) "$scenario created unexpected values."
        Assert-Test ($state.Writes -eq $(if ($scenario -eq "Enabled") { 1 } else { 0 })) "$scenario performed unexpected writes."
        $state.Creates = 0
        $state.NewValues = 0
        $state.Writes = 0
        $state.Messages.Clear()
        Invoke-CortanaScript -State $state
        Assert-Test ($state.Creates -eq 0 -and $state.NewValues -eq 0 -and $state.Writes -eq 0) "$scenario repeat run modified the registry."
        Assert-Test (($state.Messages -join "`n").Contains("No modification")) "$scenario repeat run omitted status."
    }
    Write-Host "[PASS] $scenario."
}
