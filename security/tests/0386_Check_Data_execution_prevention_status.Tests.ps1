$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0386_Check_Data_execution_prevention_status.ps1"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-DEPStatus {
    param($Policy, [switch]$QueryFailure)

    function Get-CimInstance {
        param($ClassName, $Property, $ErrorAction)
        Assert-Test ($ClassName -eq "Win32_OperatingSystem" -and $Property -eq "DataExecutionPrevention_SupportPolicy" -and $ErrorAction -eq "Stop") "Unexpected CIM query."
        if ($QueryFailure) { throw "CIM query failed." }
        [pscustomobject]@{ DataExecutionPrevention_SupportPolicy = $Policy }
    }

    & $scriptPath
}

foreach ($policy in @(0, 1, 2, 3)) {
    $output = @(Invoke-DEPStatus -Policy ([uint32]$policy))
    Assert-Test ($output.Count -eq 1 -and $output[0].Contains("DataExecutionPrevention_SupportPolicy = $policy : DEP is")) "Policy $policy omitted status."
    Write-Host "[PASS] DEP policy $policy."
}
foreach ($policy in @($null, 4)) {
    $failure = $null
    try { Invoke-DEPStatus -Policy $policy }
    catch { $failure = $_.Exception.Message }
    Assert-Test ($failure -like "*Cannot determine DEP status:*") "Unknown or missing policy did not fail."
    Write-Host "[PASS] Missing/unknown DEP policy rejected."
}
$failure = $null
try { Invoke-DEPStatus -QueryFailure }
catch { $failure = $_.Exception.Message }
Assert-Test ($failure -eq "CIM query failed.") "CIM failure was not propagated."
Write-Host "[PASS] CIM query failure propagated."
