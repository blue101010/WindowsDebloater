$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0268_Enable_cryptography_cert_pading.ps1"
$expectedPaths = @("HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config")
if ([Environment]::Is64BitOperatingSystem) {
    $expectedPaths += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
}

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-PaddingScript {
    param([hashtable]$State)

    function Test-Path {
        param($LiteralPath, $ErrorAction)
        Assert-Test ($LiteralPath -in $expectedPaths -and $ErrorAction -eq "Stop") "Unexpected path check."
        return $State.Keys.ContainsKey($LiteralPath)
    }

    function New-Item {
        param($Path, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -in $expectedPaths -and $Force -and $ErrorAction -eq "Stop") "Unexpected key creation."
        $State.Creates++
        if ($State.Failure -eq "Create") { throw "Registry Create denied." }
        $State.Keys[$Path] = @{ OtherSetting = 7 }
        return [pscustomobject]@{ Path = $Path }
    }

    function Get-ItemProperty {
        param($Path, $Name, $ErrorAction)
        Assert-Test ($Path -in $expectedPaths -and $State.Keys.ContainsKey($Path) -and -not $Name -and $ErrorAction -eq "Stop") "Read must not require a missing property."
        if ($State.Failure -eq "Read") { throw "Registry Read denied." }
        return [pscustomobject]$State.Keys[$Path]
    }

    function Set-ItemProperty {
        param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction)
        Assert-Test ($Path -in $expectedPaths -and $Name -eq "EnableCertPaddingCheck" -and $Value -ceq "1") "Unexpected registry write."
        Assert-Test ($Value -is [string] -and $Type -eq "String" -and $Force -and $ErrorAction -eq "Stop") "Unexpected write options."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Registry Write denied." }
        if ($State.Failure -ne "Mismatch") { $State.Keys[$Path][$Name] = $Value }
    }

    function Get-ItemPropertyValue {
        param($Path, $Name, $ErrorAction)
        Assert-Test ($Path -in $expectedPaths -and $Name -eq "EnableCertPaddingCheck" -and $ErrorAction -eq "Stop") "Unexpected verification."
        $State.Verifications++
        if ($State.Failure -eq "Verify") { throw "Registry Verify denied." }
        return $State.Keys[$Path][$Name]
    }

    & $scriptPath
}

foreach ($scenario in @("Missing keys", "Missing values", "Zero values", "Already configured", "Partially configured", "Create", "Read", "Write", "Verify", "Mismatch")) {
    $state = @{ Keys = @{}; Creates = 0; Writes = 0; Verifications = 0; Failure = $scenario }
    if ($scenario -notin @("Missing keys", "Create")) {
        foreach ($path in $expectedPaths) {
            $state.Keys[$path] = @{ OtherSetting = 7 }
            if ($scenario -eq "Already configured" -or ($scenario -eq "Partially configured" -and $path -eq $expectedPaths[0])) {
                $state.Keys[$path].EnableCertPaddingCheck = "1"
            }
            if ($scenario -in @("Zero values", "Mismatch")) { $state.Keys[$path].EnableCertPaddingCheck = "0" }
        }
    }
    $failure = $null
    $output = @()
    try { $output = @(Invoke-PaddingScript -State $state) }
    catch { $failure = $_.Exception.Message }
    if ($scenario -in @("Create", "Read", "Write", "Verify", "Mismatch")) {
        $expectedError = if ($scenario -eq "Mismatch") { "*Verification failed:*" } else { "Registry $scenario denied." }
        Assert-Test ($failure -like $expectedError) "${scenario}: error not propagated: $failure"
        Assert-Test (-not (($output -join "`n").Contains("configuration confirmed"))) "${scenario}: failure reported overall success."
    }
    else {
        Assert-Test ($null -eq $failure) "${scenario}: unexpected failure: $failure"
        $expectedWrites = switch ($scenario) {
            "Already configured" { 0 }
            "Partially configured" { $expectedPaths.Count - 1 }
            default { $expectedPaths.Count }
        }
        $expectedCreates = if ($scenario -eq "Missing keys") { $expectedPaths.Count } else { 0 }
        Assert-Test ($state.Writes -eq $expectedWrites -and $state.Creates -eq $expectedCreates -and $state.Verifications -eq $expectedPaths.Count) "${scenario}: unexpected operation counts."
        foreach ($path in $expectedPaths) {
            Assert-Test ($state.Keys[$path].EnableCertPaddingCheck -eq "1" -and $state.Keys[$path].OtherSetting -eq 7) "${scenario}: registry values incorrect."
        }
        Assert-Test (@($output | Where-Object { $_ -like "*[[]confirmed[]]*" }).Count -eq $expectedPaths.Count) "${scenario}: missing per-view confirmation."
        Assert-Test ($output[-1].Contains("configuration confirmed in all applicable views")) "${scenario}: missing overall status."
        $state.Writes = 0
        $state.Creates = 0
        $repeatOutput = @(Invoke-PaddingScript -State $state)
        Assert-Test ($state.Writes -eq 0 -and $state.Creates -eq 0) "${scenario}: repeat run is not idempotent."
    }
    Write-Host "[PASS] $scenario."
}
