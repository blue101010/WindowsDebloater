$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\deprecated\0179_remove-contact-support-and-windows-feedback-packages-from-windows-10.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

# Load only Remove-Package, avoiding privilege changes and real package removal.
$functionAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Remove-Package"
}, $true)
. ([scriptblock]::Create($functionAst.Extent.Text))

function Test-Path {
    param($LiteralPath, $ErrorAction)
    Assert-Test ($LiteralPath -like "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\*" -and $ErrorAction -eq "Stop") "Unexpected package check."
    if ($state.Failure -eq "Read") { throw "Registry read denied." }
    return $state.Exists
}

function Take-Over {
    param($path)
    $state.OwnershipCalls++
    throw "Ownership denied."
}

function Remove-Item {
    throw "Registry deletion must not occur after a missing key or ownership failure."
}

function Write-Host {
    param([string]$Object)
    [void]$state.Messages.Add($Object)
}

foreach ($scenario in @("Missing package", "Read failure", "Ownership failure")) {
    $state = @{
        Exists = $scenario -eq "Ownership failure"
        Failure = if ($scenario -eq "Read failure") { "Read" } else { $null }
        OwnershipCalls = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try { Remove-Package "Missing-Test-Package" }
    catch { $failure = $_.Exception.Message }
    if ($scenario -eq "Missing package") {
        Assert-Test ($null -eq $failure -and $state.OwnershipCalls -eq 0) "Missing package did not skip safely."
        Assert-Test ($state.Messages.Count -eq 1 -and $state.Messages[0].Contains("[skipped] Package is not installed: Missing-Test-Package")) "Missing package omitted skip status."
    }
    else {
        $expectedError = if ($scenario -eq "Read failure") { "Registry read denied." } else { "Ownership denied." }
        Assert-Test ($failure -eq $expectedError -and $state.Messages.Count -eq 0) "$scenario was not propagated."
        $expectedCalls = if ($scenario -eq "Ownership failure") { 1 } else { 0 }
        Assert-Test ($state.OwnershipCalls -eq $expectedCalls) "$scenario made unexpected ownership calls."
    }
    Microsoft.PowerShell.Utility\Write-Host "[PASS] $scenario."
}

$takeOverAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Take-Over"
}, $true)
. ([scriptblock]::Create($takeOverAst.Extent.Text))
$missingPath = "SOFTWARE\Copilot-Missing-Package-Test-$([guid]::NewGuid())"
$failure = $null
try { Take-Over $missingPath }
catch { $failure = $_.Exception.Message }
Assert-Test ($failure -like "*Cannot take ownership:*no longer exists.*") "Missing ownership key did not produce an explicit error: $failure"
Microsoft.PowerShell.Utility\Write-Host "[PASS] Missing ownership key is guarded (read-only registry check)."
