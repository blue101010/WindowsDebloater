$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0470_Set_default_input_method_English_US_International.ps1"
$inputTip = "0409:00020409"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-Test ($parseErrors.Count -eq 0) "Script contains syntax errors."

function New-TestLanguage {
    param([string]$LanguageTag, [string[]]$InputMethodTips)
    $tips = [System.Collections.Generic.List[string]]::new()
    foreach ($tip in $InputMethodTips) { [void]$tips.Add($tip) }
    [pscustomobject]@{ LanguageTag = $LanguageTag; InputMethodTips = $tips }
}

function Invoke-InputMethodScript {
    param([hashtable]$State)

    function Get-WinUserLanguageList {
        param($ErrorAction)
        if ($ErrorAction -ne "Stop") { throw "Language-list reads must stop on errors." }
        $State.LanguageReads++
        if ($State.Failure -eq "LanguageRead") { throw "Language-list read failed." }
        if ($State.Failure -eq "ExtraLanguage" -and $State.LanguageReads -gt 1) {
            [void]$State.LanguageList.Add((New-TestLanguage "fr-CA" @("1009:00011009")))
        }
        return ,$State.LanguageList
    }

    function New-WinUserLanguageList {
        param($Language, $ErrorAction)
        Assert-Test ($Language -eq "en-US" -and $ErrorAction -eq "Stop") "Unexpected language-list creation."
        if ($State.Failure -eq "Create") { throw "Language-list creation failed." }
        $newList = [System.Collections.ArrayList]::new()
        [void]$newList.Add((New-TestLanguage -LanguageTag "en-US" -InputMethodTips @("0409:00000409")))
        return ,$newList
    }

    function Set-WinUserLanguageList {
        param($LanguageList, [switch]$Force, $ErrorAction)
        Assert-Test ($Force -and $ErrorAction -eq "Stop") "Unexpected language-list write options."
        Assert-Test ($LanguageList.Count -eq 1 -and $LanguageList[0].LanguageTag -eq "en-US") "Expected only en-US in replacement list."
        Assert-Test ($LanguageList[0].InputMethodTips.Count -eq 1 -and $LanguageList[0].InputMethodTips[0] -eq $inputTip) "Expected only US-International in replacement list."
        $State.LanguageListWrites++
        if ($State.Failure -eq "LanguageList") { throw "Language-list write failed." }
        if ($State.Failure -eq "ExtraLayout") {
            [void]$LanguageList[0].InputMethodTips.Add("0409:00011009")
        }
        $State.LanguageList = $LanguageList
    }

    function Get-WinDefaultInputMethodOverride {
        param($ErrorAction)
        if ($ErrorAction -ne "Stop") { throw "Override reads must stop on errors." }
        if ($State.Failure -eq "OverrideRead") { throw "Override read failed." }
        if ($null -eq $State.Override) { return }
        return [pscustomobject]@{ InputMethodTip = $State.Override; Description = "Mock input method" }
    }

    function Set-WinDefaultInputMethodOverride {
        param($InputTip, $ErrorAction)
        Assert-Test ($InputTip -eq "0409:00020409" -and $ErrorAction -eq "Stop") "Unexpected default input method."
        $State.OverrideWrites++
        if ($State.Failure -eq "Override") { throw "Override write failed." }
        if ($State.Failure -ne "VerifyOverride") { $State.Override = $InputTip }
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

$cases = @(
    @{
        Name = "Replaces other languages and layouts"
        Languages = @((New-TestLanguage "fr-FR" @("040c:0000040c")), (New-TestLanguage "en-US" @("0409:00000409")))
        Override = "0409:00000409"
        ExpectedLanguageWrites = 1
        ExpectedOverrideWrites = 1
    },
    @{
        Name = "Replaces language list when en-US is missing"
        Languages = @((New-TestLanguage "fr-FR" @("040c:0000040c")))
        Override = $null
        ExpectedLanguageWrites = 1
        ExpectedOverrideWrites = 1
    },
    @{
        Name = "Removes CMS from en-US even when US-International is already default"
        Languages = @((New-TestLanguage "en-US" @("0409:00011009", "0409:00020409")))
        Override = "0409:00020409"
        ExpectedLanguageWrites = 1
        ExpectedOverrideWrites = 0
    },
    @{
        Name = "Removes duplicate US-International entries"
        Languages = @((New-TestLanguage "en-US" @("0409:00020409", "0409:00020409")))
        Override = "0409:00020409"
        ExpectedLanguageWrites = 1
        ExpectedOverrideWrites = 0
    },
    @{
        Name = "Already configured"
        Languages = @((New-TestLanguage "en-US" @("0409:00020409")))
        Override = "0409:00020409"
        ExpectedLanguageWrites = 0
        ExpectedOverrideWrites = 0
    }
)

foreach ($case in $cases) {
    $languageList = [System.Collections.ArrayList]::new()
    foreach ($language in $case.Languages) { [void]$languageList.Add($language) }
    $state = @{
        LanguageList = $languageList
        Override = $case.Override
        LanguageListWrites = 0
        OverrideWrites = 0
        LanguageReads = 0
        Messages = [System.Collections.Generic.List[string]]::new()
        Failure = $null
    }

    $result = @(Invoke-InputMethodScript -State $state)
    Assert-Test ($result.Count -eq 0) "$($case.Name): unexpected pipeline output."
    Assert-Test ($state.LanguageListWrites -eq $case.ExpectedLanguageWrites) "$($case.Name): unexpected language-list write count."
    Assert-Test ($state.OverrideWrites -eq $case.ExpectedOverrideWrites) "$($case.Name): unexpected override write count."
    Assert-Test ($state.LanguageList.Count -eq 1 -and $state.LanguageList[0].LanguageTag -eq "en-US") "$($case.Name): expected only en-US."
    $english = $state.LanguageList[0]
    Assert-Test ($english.InputMethodTips.Count -eq 1 -and $english.InputMethodTips[0] -eq $inputTip) "$($case.Name): extra layouts remain or requested layout is missing."
    Assert-Test ($state.Override -eq $inputTip) "$($case.Name): requested default was not set."
    Assert-Test (($state.Messages -join "`n").Contains("[confirmed]")) "$($case.Name): missing verification status."
    Microsoft.PowerShell.Utility\Write-Host "[PASS] $($case.Name)."
}

foreach ($failure in @("LanguageRead", "Create", "LanguageList", "OverrideRead", "Override", "ExtraLayout", "ExtraLanguage", "VerifyOverride")) {
    $languageList = [System.Collections.ArrayList]::new()
    [void]$languageList.Add((New-TestLanguage "en-US" @("0409:00000409")))
    $state = @{
        LanguageList = $languageList
        Override = "0409:00000409"
        LanguageListWrites = 0
        OverrideWrites = 0
        LanguageReads = 0
        Messages = [System.Collections.Generic.List[string]]::new()
        Failure = $failure
    }
    $errorMessage = $null
    try { Invoke-InputMethodScript -State $state } catch { $errorMessage = $_.Exception.Message }
    $expectedError = switch ($failure) {
        "LanguageRead" { "Language-list read failed." }
        "Create" { "Language-list creation failed." }
        "LanguageList" { "Language-list write failed." }
        "OverrideRead" { "Override read failed." }
        "Override" { "Override write failed." }
        "VerifyOverride" { "*Verification failed: default input method*" }
        default { "*Verification failed: expected only en-US*" }
    }
    Assert-Test ($errorMessage -like $expectedError) "$failure failure was not surfaced: '$errorMessage'."
    Assert-Test (-not ($state.Messages -join "`n").Contains("[confirmed]")) "$failure incorrectly reported success."
    Microsoft.PowerShell.Utility\Write-Host "[PASS] $failure failures are surfaced."
}

Microsoft.PowerShell.Utility\Write-Host "[PASS] Script parses in Windows PowerShell 5.1."
