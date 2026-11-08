$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0011_Disable_Collect_Activity_History_PublishUserActivities.ps1"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-Test ($parseErrors.Count -eq 0) "Script contains syntax errors."
Assert-Test (-not $ast.ScriptRequirements.IsElevationRequired) "An elevation requirement would prevent the UAC prompt."

function Invoke-ActivityHistoryScript {
    param([hashtable]$State)

    function New-Object {
        param($TypeName, $ArgumentList)
        Assert-Test ($TypeName -eq "Security.Principal.WindowsPrincipal") "Unexpected object construction."
        Assert-Test ($ArgumentList -is [Security.Principal.WindowsIdentity]) "Unexpected principal identity."
        $mockPrincipal = [pscustomobject]@{ Elevated = $State.Elevated }
        $mockPrincipal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value {
            param($Role)
            if ($Role -ne [Security.Principal.WindowsBuiltInRole]::Administrator) { throw "Unexpected role." }
            return $this.Elevated
        }
        return $mockPrincipal
    }

    function Start-Process {
        param($FilePath, $ArgumentList, $Verb, [switch]$Wait, [switch]$PassThru, $ErrorAction)
        $expectedExecutable = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
        Assert-Test ($FilePath -eq (Join-Path $PSHOME $expectedExecutable)) "Unexpected PowerShell executable."
        Assert-Test ($ArgumentList -eq "-NoProfile -File `"$((Resolve-Path $scriptPath).Path)`"") "Script path must be quoted."
        Assert-Test ($Verb -eq "RunAs" -and $Wait -and $PassThru -and $ErrorAction -eq "Stop") "Unexpected elevation options."
        $State.Launches++
        if ($State.Failure -eq "Elevate") { throw "UAC cancelled." }
        return [pscustomobject]@{ ExitCode = $State.ExitCode }
    }

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $ErrorAction -eq "Stop") "Unexpected path check."
        if ($State.Failure -eq "Path") { throw "Registry Path denied." }
        return $State.KeyExists
    }

    function New-Item {
        param($Path, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $Force -and $ErrorAction -eq "Stop") "Unexpected key creation."
        $State.Creates++
        if ($State.Failure -eq "Create") { throw "Registry Create denied." }
        $State.KeyExists = $true
    }

    function Get-ItemProperty {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $State.KeyExists -and $ErrorAction -eq "Stop") "Unexpected registry read."
        $State.Reads++
        if ($State.Failure -eq "Read" -or ($State.Failure -eq "ReadBack" -and $State.Reads -eq 2)) {
            throw "Registry $($State.Failure) denied."
        }
        return $State.Properties
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $Name -eq "PublishUserActivities") "Unexpected write target."
        Assert-Test ($Value -eq 0 -and $Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        if ($State.Failure -ne "Verify") { $State.Properties = [pscustomobject]@{ PublishUserActivities = 0 } }
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($case in @(
    @{ Name = "Missing key"; KeyExists = $false; Properties = [pscustomobject]@{}; Creates = 1; Reads = 2; Writes = 1 },
    @{ Name = "Missing value"; KeyExists = $true; Properties = [pscustomobject]@{ OtherPolicy = 1 }; Creates = 0; Reads = 2; Writes = 1 },
    @{ Name = "Publishing enabled"; KeyExists = $true; Properties = [pscustomobject]@{ PublishUserActivities = 1 }; Creates = 0; Reads = 2; Writes = 1 },
    @{ Name = "Already configured"; KeyExists = $true; Properties = [pscustomobject]@{ PublishUserActivities = 0 }; Creates = 0; Reads = 1; Writes = 0 },
    @{ Name = "Path failure"; KeyExists = $false; Creates = 0; Reads = 0; Writes = 0; Failure = "Path" },
    @{ Name = "Creation failure"; KeyExists = $false; Creates = 1; Reads = 0; Writes = 0; Failure = "Create" },
    @{ Name = "Read failure"; KeyExists = $true; Creates = 0; Reads = 1; Writes = 0; Failure = "Read" },
    @{ Name = "Write failure"; KeyExists = $true; Properties = [pscustomobject]@{}; Creates = 0; Reads = 1; Writes = 1; Failure = "Write" },
    @{ Name = "Read-back failure"; KeyExists = $true; Properties = [pscustomobject]@{}; Creates = 0; Reads = 2; Writes = 1; Failure = "ReadBack" },
    @{ Name = "Verification failure"; KeyExists = $true; Properties = [pscustomobject]@{}; Creates = 0; Reads = 2; Writes = 1; Failure = "Verify" }
)) {
    $state = @{
        KeyExists = $case.KeyExists
        Properties = $case.Properties
        Failure = $case.Failure
        Elevated = $true
        Launches = 0
        Creates = 0
        Reads = 0
        Writes = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try {
        $result = @(Invoke-ActivityHistoryScript -State $state)
        Assert-Test ($result.Count -eq 0) "Unexpected pipeline output."
    }
    catch { $failure = $_.Exception.Message }
    $expectedError = if ($case.Failure -eq "Verify") {
        "PublishUserActivities verification failed: expected 0 after the registry write."
    }
    elseif ($case.Failure) { "Registry $($case.Failure) denied." }
    else { $null }
    Assert-Test ($failure -eq $expectedError) "$($case.Name): unexpected error '$failure'."
    Assert-Test ($state.Launches -eq 0) "$($case.Name): already-elevated execution must not prompt."
    foreach ($counter in @("Creates", "Reads", "Writes")) {
        Assert-Test ($state[$counter] -eq $case[$counter]) "$($case.Name): unexpected $counter count."
    }
    $output = $state.Messages -join "`n"
    if ($case.Failure) {
        Assert-Test (-not $output.Contains("Updated value") -and -not $output.Contains("No change")) "$($case.Name): failure reported success."
    }
    elseif ($case.Writes -eq 1) {
        Assert-Test ($output.Contains("Updated value of PublishUserActivities: 0")) "$($case.Name): missing verified success."
        if (-not $case.Properties.PSObject.Properties["PublishUserActivities"]) {
            Assert-Test ($output.Contains("PublishUserActivities does not exist")) "$($case.Name): missing absent-value message."
        }
    }
    else {
        Assert-Test ($output.Contains("No change")) "$($case.Name): missing no-change message."
    }
    Write-Host "[PASS] $($case.Name)."
}

foreach ($case in @(
    @{ Name = "UAC approved"; ExitCode = 0 },
    @{ Name = "UAC cancelled or launch denied"; Failure = "Elevate"; Error = "Administrator elevation failed or was cancelled: UAC cancelled." },
    @{ Name = "Elevated script failed"; ExitCode = 1; Error = "The elevated script failed with exit code 1." }
)) {
    $state = @{
        Elevated = $false
        Failure = $case.Failure
        ExitCode = $case.ExitCode
        Launches = 0
        Creates = 0
        Reads = 0
        Writes = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try {
        $result = @(Invoke-ActivityHistoryScript -State $state)
        Assert-Test ($result.Count -eq 0) "Unexpected elevation pipeline output."
    }
    catch { $failure = $_.Exception.Message }
    Assert-Test ($failure -eq $case.Error) "$($case.Name): unexpected error '$failure'."
    Assert-Test ($state.Launches -eq 1) "$($case.Name): expected one UAC request."
    Assert-Test ($state.Creates -eq 0 -and $state.Reads -eq 0 -and $state.Writes -eq 0) "$($case.Name): unelevated process accessed the registry."
    Assert-Test (($state.Messages -join "`n").Contains("Requesting administrator privileges through UAC")) "$($case.Name): missing UAC message."
    Write-Host "[PASS] $($case.Name)."
}
