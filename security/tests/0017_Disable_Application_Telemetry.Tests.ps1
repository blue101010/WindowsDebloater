$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0017_Disable_Application_Telemetry.ps1"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-Test ($parseErrors.Count -eq 0) "Script contains syntax errors."
Assert-Test (-not $ast.ScriptRequirements.IsElevationRequired) "An elevation requirement would prevent UAC."

function Invoke-TelemetryScript {
    param([hashtable]$State)

    function New-Object {
        param($TypeName, $ArgumentList)
        Assert-Test ($TypeName -eq "Security.Principal.WindowsPrincipal" -and $ArgumentList -is [Security.Principal.WindowsIdentity]) "Unexpected principal construction."
        $principal = [pscustomobject]@{ Elevated = $State.Elevated }
        $principal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value {
            param($Role)
            if ($Role -ne [Security.Principal.WindowsBuiltInRole]::Administrator) { throw "Unexpected role." }
            return $this.Elevated
        }
        return $principal
    }

    function Start-Process {
        param($FilePath, $ArgumentList, $Verb, [switch]$Wait, [switch]$PassThru, $ErrorAction)
        $executable = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
        Assert-Test ($FilePath -eq (Join-Path $PSHOME $executable)) "Unexpected executable."
        Assert-Test ($ArgumentList -eq "-NoProfile -File `"$((Resolve-Path $scriptPath).Path)`"") "Unexpected script arguments."
        Assert-Test ($Verb -eq "RunAs" -and $Wait -and $PassThru -and $ErrorAction -eq "Stop") "Unexpected UAC options."
        $State.Launches++
        if ($State.Failure -eq "Elevate") { throw "UAC cancelled." }
        return [pscustomobject]@{ ExitCode = $State.ExitCode }
    }

    function Test-Path {
        param($Path, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $ErrorAction -eq "Stop") "Unexpected path check."
        $State.Checks++
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
        Assert-Test ($Path -eq $registryPath -and $State.KeyExists -and $ErrorAction -eq "Stop") "Unexpected read."
        $State.Reads++
        if ($State.Failure -eq "Read" -or ($State.Failure -eq "ReadBack" -and $State.Reads -eq 2)) {
            throw "Registry $($State.Failure) denied."
        }
        return $State.Properties
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -eq $registryPath -and $Name -eq "AITEnable") "Unexpected write target."
        Assert-Test ($Value -eq 0 -and $Type -eq "DWORD" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        if ($State.Failure -ne "Verify") { $State.Properties = [pscustomobject]@{ AITEnable = 0 } }
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($case in @(
    @{ Name = "Missing key"; KeyExists = $false; Creates = 1; Reads = 2; Writes = 1 },
    @{ Name = "Missing value"; KeyExists = $true; Creates = 0; Reads = 2; Writes = 1 },
    @{ Name = "Telemetry enabled"; KeyExists = $true; Value = 1; Creates = 0; Reads = 2; Writes = 1 },
    @{ Name = "Already disabled"; KeyExists = $true; Value = 0; Creates = 0; Reads = 1; Writes = 0 },
    @{ Name = "Path failure"; Failure = "Path"; Creates = 0; Reads = 0; Writes = 0 },
    @{ Name = "Creation failure"; Failure = "Create"; Creates = 1; Reads = 0; Writes = 0 },
    @{ Name = "Read failure"; KeyExists = $true; Failure = "Read"; Creates = 0; Reads = 1; Writes = 0 },
    @{ Name = "Write failure"; KeyExists = $true; Failure = "Write"; Creates = 0; Reads = 1; Writes = 1 },
    @{ Name = "Read-back failure"; KeyExists = $true; Failure = "ReadBack"; Creates = 0; Reads = 2; Writes = 1 },
    @{ Name = "Verification failure"; KeyExists = $true; Failure = "Verify"; Creates = 0; Reads = 2; Writes = 1 },
    @{ Name = "UAC approved"; UAC = $true; ExitCode = 0; Creates = 0; Reads = 0; Writes = 0 },
    @{ Name = "UAC cancelled"; UAC = $true; Failure = "Elevate"; Creates = 0; Reads = 0; Writes = 0 },
    @{ Name = "Elevated script failed"; UAC = $true; ExitCode = 1; Creates = 0; Reads = 0; Writes = 0 }
)) {
    $properties = if ($case.ContainsKey("Value")) { [pscustomobject]@{ AITEnable = $case.Value; OtherPolicy = 1 } } else { [pscustomobject]@{ OtherPolicy = 1 } }
    $state = @{
        Elevated = -not $case.UAC
        KeyExists = $case.KeyExists
        Properties = $properties
        Failure = $case.Failure
        ExitCode = $case.ExitCode
        Checks = 0
        Launches = 0
        Creates = 0
        Reads = 0
        Writes = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try {
        $result = @(Invoke-TelemetryScript -State $state)
        Assert-Test ($result.Count -eq 0) "Unexpected pipeline output."
    }
    catch { $failure = $_.Exception.Message }
    $expectedError = if ($case.Failure -eq "Verify") { "AITEnable verification failed: expected 0 after the registry write." }
    elseif ($case.Failure -eq "Elevate") { "Administrator elevation failed or was cancelled: UAC cancelled." }
    elseif ($case.Failure) { "Registry $($case.Failure) denied." }
    elseif ($case.ExitCode -eq 1) { "The elevated script failed with exit code 1." }
    else { $null }
    Assert-Test ($failure -eq $expectedError) "$($case.Name): unexpected error '$failure'."
    foreach ($counter in @("Creates", "Reads", "Writes")) {
        Assert-Test ($state[$counter] -eq $case[$counter]) "$($case.Name): unexpected $counter count."
    }
    $expectedLaunches = if ($case.UAC) { 1 } else { 0 }
    $expectedChecks = if ($case.UAC) { 0 } else { 1 }
    Assert-Test ($state.Launches -eq $expectedLaunches -and $state.Checks -eq $expectedChecks) "$($case.Name): unexpected UAC or registry access."
    $output = $state.Messages -join "`n"
    if ($expectedError -or $case.UAC) {
        Assert-Test (-not $output.Contains("has been disabled") -and -not $output.Contains("[no change]")) "$($case.Name): false local success."
    }
    elseif ($case.Writes -eq 1) {
        Assert-Test ($output.Contains("has been disabled")) "$($case.Name): missing success."
        if (-not $case.ContainsKey("Value")) {
            Assert-Test ($output.Contains("AITEnable does not exist. Creating it")) "$($case.Name): missing absent-value message."
        }
    }
    else {
        Assert-Test ($output.Contains("[no change]")) "$($case.Name): missing no-change message."
    }
    Write-Host "[PASS] $($case.Name)."
}
