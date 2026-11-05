$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0222_block_mshta.ps1"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-BlockScript {
    param([hashtable]$State, [switch]$WhatIf)

    function Get-AppLockerPolicy {
        param([switch]$Effective, [switch]$Xml, $ErrorAction)
        Assert-Test ($Effective -and $Xml -and $ErrorAction -eq "Stop") "Unexpected policy read."
        $State.Reads++
        if ($State.Failure -eq "Read") { throw "Policy read denied." }
        if ($State.Merges -eq 0) { return $State.Existing.OuterXml }
        if ($State.Failure -eq "Override") { return '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly" /></AppLockerPolicy>' }
        return $State.Merged.OuterXml
    }

    function Test-AppLockerPolicy {
        param($XmlPolicy, $Path, $User, $ErrorAction)
        Assert-Test ($User -eq "S-1-1-0" -and $ErrorAction -eq "Stop") "Unexpected policy test."
        [xml]$candidate = Get-Content -LiteralPath $XmlPolicy -Raw
        $State.Tests++
        $exe = $candidate.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Exe']")
        Assert-Test ($exe.EnforcementMode -eq "Enabled") "Executable enforcement is missing."
        Assert-Test ($exe.SelectNodes("*[@Action='Deny' and @UserOrGroupSid='S-1-1-0']").Count -eq 2) "Expected two deny rules."
        Assert-Test ($null -ne $exe.SelectSingleNode("FilePathRule/Conditions/FilePathCondition[@Path='*\mshta.exe']")) "Filename block missing."
        Assert-Test ($null -ne $exe.SelectSingleNode("FilePublisherRule/Conditions/FilePublisherCondition[@PublisherName='O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US' and @ProductName='*' and @BinaryName='MSHTA.EXE']/BinaryVersionRange[@LowSection='*' and @HighSection='*']")) "Renamed signed binary block missing."
        foreach ($file in $Path) {
            [pscustomobject]@{
                FilePath = $file
                PolicyDecision = if ($State.Failure -eq "Test") { "Allowed" } else { "Denied" }
            }
        }
    }

    function Set-AppLockerPolicy {
        param($XmlPolicy, [switch]$Merge, $ErrorAction)
        Assert-Test ($Merge -and $ErrorAction -eq "Stop") "Policy must be merged, not replaced."
        [xml]$candidate = Get-Content -LiteralPath $XmlPolicy -Raw
        $State.PolicyPath = $XmlPolicy
        $State.Merges++
        if ($State.Failure -eq "Merge") { throw "Policy merge denied." }
        $State.Merged = [xml]$State.Existing.OuterXml
        foreach ($collection in $candidate.AppLockerPolicy.RuleCollection) {
            $existing = $State.Merged.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='$($collection.Type)']")
            if ($null -eq $existing) {
                $State.Merged.AppLockerPolicy.AppendChild($State.Merged.ImportNode($collection, $true)) | Out-Null
            }
            else {
                $existing.SetAttribute("EnforcementMode", $collection.EnforcementMode)
                foreach ($rule in $collection.ChildNodes) {
                    if ($null -eq $existing.SelectSingleNode("*[@Id='$($rule.Id)']")) {
                        $existing.AppendChild($State.Merged.ImportNode($rule, $true)) | Out-Null
                    }
                }
            }
        }
    }

    function Start-Process {
        param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, [switch]$NoNewWindow, $ErrorAction)
        Assert-Test ($FilePath -eq (Join-Path $env:windir "System32\sc.exe") -and ($ArgumentList -join " ") -eq "config AppIDSvc start= auto") "Unexpected process launch."
        Assert-Test ($Wait -and $PassThru -and $NoNewWindow -and $ErrorAction -eq "Stop") "Unexpected process options."
        $State.ServiceChanges++
        [pscustomobject]@{ ExitCode = if ($State.Failure -eq "Service") { 5 } else { 0 } }
    }

    function Start-Service {
        param($Name, $ErrorAction)
        Assert-Test ($Name -eq "AppIDSvc" -and $ErrorAction -eq "Stop") "Unexpected service start."
    }

    function Get-Service {
        param($Name, $ErrorAction)
        Assert-Test ($Name -eq "AppIDSvc" -and $ErrorAction -eq "Stop") "Unexpected service read."
        [pscustomobject]@{ Status = "Running"; StartType = "Automatic" }
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath -Confirm:$false -WhatIf:$WhatIf
}

$emptyPolicy = '<AppLockerPolicy Version="1" />'
$existingPolicy = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="98c6fb5a-3df4-4c27-8b81-b37b2c1148b1" Name="Existing allow" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="AuditOnly">
    <FilePublisherRule Id="b6306726-8435-44b3-bf29-c322ec368f01" Name="Existing packaged rule" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
'@

foreach ($scenario in @("Empty policy", "Existing policy", "Repeat run", "Audit-only", "WhatIf", "Read", "Test", "Merge", "Service", "Override")) {
    [xml]$existing = if ($scenario -in @("Existing policy", "Repeat run", "Audit-only")) { $existingPolicy } else { $emptyPolicy }
    if ($scenario -eq "Audit-only") { $existing.AppLockerPolicy.RuleCollection[0].EnforcementMode = "AuditOnly" }
    $state = @{
        Existing = $existing
        Merged = $null
        Failure = $scenario
        Reads = 0
        Tests = 0
        Merges = 0
        ServiceChanges = 0
        PolicyPath = $null
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try { Invoke-BlockScript -State $state -WhatIf:($scenario -eq "WhatIf") }
    catch { $failure = $_.Exception.Message }
    if ($scenario -in @("Empty policy", "Existing policy", "Repeat run")) {
        Assert-Test ($null -eq $failure) "$scenario failed: $failure"
        Assert-Test ($state.Merges -eq 1 -and $state.Tests -eq 2 -and $state.ServiceChanges -eq 1) "$scenario did not apply and verify."
        Assert-Test ($state.Messages.Count -eq 1 -and $state.Messages[0].Contains("[confirmed]")) "$scenario omitted status."
        if ($scenario -eq "Empty policy") {
            $generatedPolicy = [xml]$state.Merged.OuterXml
            Assert-Test ($null -ne $state.Merged.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Exe']/FilePathRule[@Action='Allow']/Conditions/FilePathCondition[@Path='*']")) "Empty policy lacks a safe baseline."
            Assert-Test ($null -ne $state.Merged.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Appx']/FilePublisherRule[@Action='Allow']")) "Empty policy would block packaged apps."
        }
        else {
            Assert-Test ($null -eq $state.Merged.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Exe']/FilePathRule[@Action='Allow']/Conditions/FilePathCondition[@Path='*']")) "Existing policy was weakened."
            Assert-Test ($state.Merged.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Appx']").OuterXml -eq $existing.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Appx']").OuterXml) "Existing packaged-app policy changed."
            Assert-Test ($null -ne $state.Merged.SelectSingleNode("//*[@Id='98c6fb5a-3df4-4c27-8b81-b37b2c1148b1']")) "Existing executable rule lost."
        }
        if ($scenario -eq "Repeat run") {
            $state.Existing = $state.Merged
            $state.Merges = 0
            Invoke-BlockScript -State $state
            Assert-Test ($state.Merged.SelectNodes("/AppLockerPolicy/RuleCollection[@Type='Exe']/*").Count -eq 3) "Repeat run duplicated rules."
        }
    }
    elseif ($scenario -eq "WhatIf") {
        Assert-Test ($null -eq $failure -and $state.Merges -eq 0 -and $state.ServiceChanges -eq 0 -and $state.Tests -eq 0 -and $state.Messages.Count -eq 0) "WhatIf caused changes or success status."
    }
    else {
        $pattern = switch ($scenario) {
            "Audit-only" { "*Existing executable rules are not enforced*" }
            "Read" { "Policy read denied." }
            "Test" { "*Proposed policy does not explicitly deny*" }
            "Merge" { "Policy merge denied." }
            "Service" { "*Failed to configure Application Identity*" }
            "Override" { "*Effective executable policy is not enforced*" }
        }
        Assert-Test ($failure -like $pattern -and $state.Messages.Count -eq 0) "$scenario did not fail explicitly: $failure"
        if ($scenario -in @("Audit-only", "Read", "Test")) { Assert-Test ($state.Merges -eq 0 -and $state.ServiceChanges -eq 0) "$scenario mutated system state." }
    }
    if ($state.PolicyPath) { Assert-Test (-not (Test-Path -LiteralPath $state.PolicyPath)) "$scenario left a temporary policy file." }
    Write-Host "[PASS] $scenario."
}

# Evaluate real policy XML without installing it or executing any binaries.
$tempPath = Join-Path ([IO.Path]::GetTempPath()) ("mshta-policy-test-" + [guid]::NewGuid())
$xmlPath = Join-Path $tempPath "policy.xml"
$renamedPath = Join-Path $tempPath "renamed-host.exe"
try {
    New-Item -ItemType Directory -Path $tempPath | Out-Null
    $generatedPolicy.Save($xmlPath)
    $mshtaPath = Join-Path $env:windir "System32\mshta.exe"
    $unrelatedPath = Join-Path $env:windir "System32\cmd.exe"
    Copy-Item -LiteralPath $mshtaPath -Destination $renamedPath
    $paths = @($mshtaPath, $renamedPath, $unrelatedPath)
    $wow64Path = Join-Path $env:windir "SysWOW64\mshta.exe"
    if (Test-Path -LiteralPath $wow64Path) { $paths += $wow64Path }
    $results = @(AppLocker\Test-AppLockerPolicy -XmlPolicy $xmlPath -Path $paths -User "S-1-1-0" -ErrorAction Stop)
    Assert-Test ($results.Count -eq $paths.Count) "Real AppLocker evaluation returned an unexpected number of results."
    foreach ($result in $results) {
        $expectedDecision = if ($result.FilePath -eq $unrelatedPath) { "Allowed" } else { "Denied" }
        Assert-Test ($result.PolicyDecision -eq $expectedDecision) "Real AppLocker evaluation returned $($result.PolicyDecision) for $($result.FilePath); expected $expectedDecision."
    }
    Write-Host "[PASS] Real AppLocker evaluates installed and renamed mshta as Denied, and unrelated cmd.exe as Allowed."
}
finally {
    foreach ($path in @($renamedPath, $xmlPath)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath }
}
