<#
.SYNOPSIS
Blocks mshta.exe using enforced AppLocker executable deny rules.

.DESCRIPTION
Merges local rules for Everyone without replacing existing policy. Blocks files
named mshta.exe by path and Microsoft-signed files whose publisher binary name is MSHTA.EXE,
including renamed signed copies. Does not block renamed unsigned replacements.
If no effective executable rules exist, adds an allow-all baseline so unrelated
executables are not implicitly denied. Refuses to enforce existing audit-only or
not-configured executable rules. If no packaged-app rules exist, adds an
allow-all signed packaged-app rule to avoid blocking Store apps when executable
enforcement is enabled. Existing rules in other collections are not modified.

Requires administrator privileges, AppLocker cmdlets and an OS supporting
AppLocker enforcement. Configures Application Identity for automatic startup
and starts it; this can also activate other existing AppLocker collections.
Automatic startup cannot be reverted to Manual with sc.exe. Review existing
policy and take a system backup before applying. Domain/MDM policy can override
local enforcement; failed verification throws and does not roll back changes.
Confirmation describes policy evaluation, not a live execution test.

.EXAMPLE
.\0222_block_mshta.ps1 -WhatIf

.EXAMPLE
.\0222_block_mshta.ps1

.LINK
https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param()

$ErrorActionPreference = "Stop"
$title = "[0222_block_mshta]"
foreach ($command in @("Get-AppLockerPolicy", "Set-AppLockerPolicy", "Test-AppLockerPolicy")) {
    Get-Command -Name $command -ErrorAction Stop | Out-Null
}

[xml]$effectivePolicy = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
$exeCollection = $effectivePolicy.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Exe']")
if ($null -ne $exeCollection -and $exeCollection.ChildNodes.Count -gt 0 -and $exeCollection.EnforcementMode -ne "Enabled") {
    throw "$title Existing executable rules are not enforced. Review and enforce them separately before running this script."
}

[xml]$policy = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="c675873b-e712-43ff-9c59-ab238d0b1951" Name="0222 Block mshta.exe by filename" Description="Block mshta.exe in any directory" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\mshta.exe" /></Conditions>
    </FilePathRule>
    <FilePublisherRule Id="e13b19e5-8f70-488f-b66a-72a447df166b" Name="0222 Block signed MSHTA.EXE" Description="Block signed mshta including renamed copies" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="MSHTA.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
'@
if ($null -eq $exeCollection -or $exeCollection.ChildNodes.Count -eq 0) {
    [xml]$baseline = @'
<FilePathRule Id="f489e730-a79e-4250-b767-f87362c9a7ac" Name="0222 Allow unrelated executables" Description="Deny-list baseline for an otherwise empty executable collection" UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions><FilePathCondition Path="*" /></Conditions>
</FilePathRule>
'@
    $policy.AppLockerPolicy.RuleCollection.AppendChild($policy.ImportNode($baseline.DocumentElement, $true)) | Out-Null
}

$appxCollection = $effectivePolicy.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Appx']")
if ($null -eq $appxCollection -or $appxCollection.ChildNodes.Count -eq 0) {
    [xml]$appxBaseline = @'
<RuleCollection Type="Appx" EnforcementMode="Enabled">
  <FilePublisherRule Id="9b0038d1-d8f2-4e16-bdc4-e1e15d9d8f2c" Name="0222 Allow signed packaged apps" Description="Preserve packaged-app access when enabling executable rules" UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
      <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
        <BinaryVersionRange LowSection="*" HighSection="*" />
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>
</RuleCollection>
'@
    $policy.AppLockerPolicy.AppendChild($policy.ImportNode($appxBaseline.DocumentElement, $true)) | Out-Null
}

$mshtaPaths = @(
    foreach ($relativePath in @("System32\mshta.exe", "SysWOW64\mshta.exe")) {
        $path = Join-Path $env:windir $relativePath
        if (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop) { $path }
    }
)
if ($mshtaPaths.Count -eq 0) {
    throw "$title No installed mshta.exe was found; cannot verify the block."
}

if (-not $PSCmdlet.ShouldProcess("Local AppLocker policy and AppIDSvc", "Merge enforced mshta deny rules and enable Application Identity automatic startup")) {
    return
}

$policyPath = Join-Path ([IO.Path]::GetTempPath()) ("mshta-applocker-" + [guid]::NewGuid() + ".xml")
try {
    $policy.Save($policyPath)
    $results = @(Test-AppLockerPolicy -XmlPolicy $policyPath -Path $mshtaPaths -User "S-1-1-0" -ErrorAction Stop)
    if ($results.Count -ne $mshtaPaths.Count -or @($results | Where-Object { $_.PolicyDecision -ne "Denied" }).Count -gt 0) {
        throw "$title Proposed policy does not explicitly deny every installed mshta.exe."
    }
    Set-AppLockerPolicy -XmlPolicy $policyPath -Merge -ErrorAction Stop

    $scPath = Join-Path $env:windir "System32\sc.exe"
    $sc = Start-Process -FilePath $scPath -ArgumentList @("config", "AppIDSvc", "start=", "auto") -Wait -PassThru -NoNewWindow -ErrorAction Stop
    if ($sc.ExitCode -ne 0) {
        throw "$title Failed to configure Application Identity automatic startup (sc.exe exit $($sc.ExitCode))."
    }
    Start-Service -Name AppIDSvc -ErrorAction Stop
    $service = Get-Service -Name AppIDSvc -ErrorAction Stop
    if ($service.Status -ne "Running" -or $service.StartType -ne "Automatic") {
        throw "$title Application Identity is not running with automatic startup; enforcement is not confirmed."
    }

    [xml]$confirmedPolicy = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
    $confirmedCollection = $confirmedPolicy.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='Exe']")
    if ($null -eq $confirmedCollection -or $confirmedCollection.EnforcementMode -ne "Enabled") {
        throw "$title Effective executable policy is not enforced; check domain/MDM policy."
    }
    foreach ($rule in $policy.SelectNodes("/AppLockerPolicy/RuleCollection/*")) {
        $collectionType = $rule.ParentNode.GetAttribute("Type")
        $confirmedRule = $confirmedPolicy.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='$collectionType']/*[@Id='$($rule.Id)']")
        if ($null -eq $confirmedRule -or $confirmedRule.LocalName -ne $rule.LocalName -or $confirmedRule.Action -ne $rule.Action -or $confirmedRule.UserOrGroupSid -ne "S-1-1-0" -or $null -ne $confirmedRule.SelectSingleNode("Exceptions")) {
            throw "$title Effective policy does not contain the expected rule '$($rule.Name)'."
        }
        $condition = $rule.SelectSingleNode("Conditions/*")
        $confirmedCondition = $confirmedRule.SelectSingleNode("Conditions/*")
        if ($null -eq $confirmedCondition -or $confirmedCondition.LocalName -ne $condition.LocalName) {
            throw "$title Effective rule '$($rule.Name)' has a different condition."
        }
        foreach ($attribute in $condition.Attributes) {
            if ($confirmedCondition.GetAttribute($attribute.Name) -ne $attribute.Value) {
                throw "$title Effective rule '$($rule.Name)' has a different $($attribute.Name)."
            }
        }
        if ($condition.LocalName -eq "FilePublisherCondition") {
            $version = $confirmedCondition.SelectSingleNode("BinaryVersionRange")
            if ($null -eq $version -or $version.LowSection -ne "*" -or $version.HighSection -ne "*") {
                throw "$title Effective publisher rule '$($rule.Name)' does not cover all versions."
            }
        }
    }
    $confirmedPolicy.Save($policyPath)
    $results = @(Test-AppLockerPolicy -XmlPolicy $policyPath -Path $mshtaPaths -User "S-1-1-0" -ErrorAction Stop)
    if ($results.Count -ne $mshtaPaths.Count -or @($results | Where-Object { $_.PolicyDecision -ne "Denied" }).Count -gt 0) {
        throw "$title Effective policy does not explicitly deny every installed mshta.exe."
    }
    Write-Host "$title [confirmed] AppLocker denies mshta.exe for Everyone; executable rules are enforced and AppIDSvc is running."
}
finally {
    if (Test-Path -LiteralPath $policyPath -ErrorAction Stop) {
        Remove-Item -LiteralPath $policyPath -Force -ErrorAction Stop
    }
}
