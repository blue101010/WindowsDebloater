$ErrorActionPreference = "Stop"
$path = Join-Path $PSScriptRoot "..\security\default\0437_Check_wifi.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$functionAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Invoke-ConnectivityCheck"
}, $true)
. ([scriptblock]::Create($functionAst.Extent.Text))

function Resolve-DnsName {
    param($Name, $Type, $ErrorAction)
    [pscustomobject]@{ IPAddress = "192.0.2.1" }
}

function New-Object {
    param($TypeName)
    Assert-Test ($TypeName -eq "System.Net.NetworkInformation.Ping") "Unexpected object creation."
    $fake = [pscustomobject]@{}
    $fake | Add-Member -MemberType ScriptMethod -Name Send -Value {
        param($Target, $Timeout)
        Assert-Test ($Target -eq "test.invalid" -and $Timeout -eq 3000) "Incorrect ping target or timeout."
        $state.Calls++
        if ($state.Fail) { throw "Ping failed." }
        [pscustomobject]@{ Status = $state.Status }
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $state.Disposed = $true }
    return $fake
}

function Write-Host {
    param($Object, $ForegroundColor)
    if ($Object -like "*ICMP Reachability*") {
        $state.Message = $Object
        $state.Color = $ForegroundColor
    }
}

function Write-Warning {
    param($Message)
    $state.Warning = $Message
}

foreach ($scenario in @("Success", "TimedOut", "Error")) {
    $state = @{ Status = $scenario; Fail = $scenario -eq "Error"; Calls = 0; Disposed = $false; Message = $null; Warning = $null }
    Invoke-ConnectivityCheck -TargetHost "test.invalid" -PingTimeoutSeconds 3 -PingCount 2
    Assert-Test ($state.Disposed) "$scenario did not dispose Ping."
    if ($scenario -eq "Error") {
        Assert-Test ($state.Calls -eq 1 -and $state.Warning -like "*ICMP Reachability*Failed*" -and $null -eq $state.Message) "Ping error was not reported."
    }
    else {
        $expectedColor = if ($scenario -eq "Success") { "Green" } else { "Yellow" }
        $expectedMessage = if ($scenario -eq "Success") { "Success" } else { "No reply" }
        Assert-Test ($state.Calls -eq 2 -and $state.Color -eq $expectedColor -and $state.Message.Contains($expectedMessage)) "Incorrect ping status."
    }
    Microsoft.PowerShell.Utility\Write-Host "[PASS] $scenario (mocked DNS and ICMP)."
}
Microsoft.PowerShell.Utility\Write-Host "[PASS] Entire script parses in Windows PowerShell 5.1."
