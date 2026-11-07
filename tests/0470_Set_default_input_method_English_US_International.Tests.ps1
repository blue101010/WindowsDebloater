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
        return ,$State.LanguageList
    }

    function New-WinUserLanguageList {
        param($Language, $ErrorAction)
        Assert-Test ($Language -eq "en-US" -and $ErrorAction -eq "Stop") "Unexpected language-list creation."
        $newList = [System.Collections.ArrayList]::new()
        [void]$newList.Add((New-TestLanguage -LanguageTag "en-US" -InputMethodTips @("0409:00000409")))
        return ,$newList
    }

    function Set-WinUserLanguageList {
        param($LanguageList, [switch]$Force, $ErrorAction)
        Assert-Test ($Force -and $ErrorAction -eq "Stop") "Unexpected language-list write options."
        $State.LanguageListWrites++
        if ($State.Failure -eq "LanguageList") { throw "Language-list write failed." }
        $State.LanguageList = $LanguageList
    }

    function Get-WinDefaultInputMethodOverride {
        param($ErrorAction)
        if ($ErrorAction -ne "Stop") { throw "Override reads must stop on errors." }
        return [pscustomobject]@{ InputTip = $State.Override }
    }

    function Set-WinDefaultInputMethodOverride {
        param($InputTip, $ErrorAction)
        Assert-Test ($InputTip -eq "0409:00020409" -and $ErrorAction -eq "Stop") "Unexpected default input method."
        $State.OverrideWrites++
        if ($State.Failure -eq "Override") { throw "Override write failed." }
        $State.Override = $InputTip
    }

    & $scriptPath
}

$cases = @(
    @{
        Name = "Adds layout and sets default"
        Languages = @((New-TestLanguage "fr-FR" @("040c:0000040c")), (New-TestLanguage "en-US" @("0409:00000409")))
        Override = "0409:00000409"
        ExpectedLanguageWrites = 1
        ExpectedOverrideWrites = 1
        ExpectedLanguages = 2
    },
    @{
        Name = "Adds en-US without removing other languages"
        Languages = @((New-TestLanguage "fr-FR" @("040c:0000040c")))
        Override = $null
        ExpectedLanguageWrites = 1
        ExpectedOverrideWrites = 1
        ExpectedLanguages = 2
    },
    @{
        Name = "Already configured"
        Languages = @((New-TestLanguage "en-US" @("0409:00020409", "0409:00000409")))
        Override = "0409:00020409"
        ExpectedLanguageWrites = 0
        ExpectedOverrideWrites = 0
        ExpectedLanguages = 1
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
        Failure = $null
    }

    $result = @(Invoke-InputMethodScript -State $state)
    Assert-Test ($result.Count -eq 0) "$($case.Name): unexpected pipeline output."
    Assert-Test ($state.LanguageListWrites -eq $case.ExpectedLanguageWrites) "$($case.Name): unexpected language-list write count."
    Assert-Test ($state.OverrideWrites -eq $case.ExpectedOverrideWrites) "$($case.Name): unexpected override write count."
    Assert-Test ($state.LanguageList.Count -eq $case.ExpectedLanguages) "$($case.Name): existing languages were not preserved."
    $english = $state.LanguageList | Where-Object { $_.LanguageTag -eq "en-US" } | Select-Object -First 1
    Assert-Test ($null -ne $english -and $english.InputMethodTips -contains $inputTip) "$($case.Name): requested layout is missing."
    Assert-Test ($state.Override -eq $inputTip) "$($case.Name): requested default was not set."
    Microsoft.PowerShell.Utility\Write-Host "[PASS] $($case.Name)."
}

foreach ($failure in @("LanguageList", "Override")) {
    $languageList = [System.Collections.ArrayList]::new()
    [void]$languageList.Add((New-TestLanguage "en-US" @("0409:00000409")))
    $state = @{
        LanguageList = $languageList
        Override = "0409:00000409"
        LanguageListWrites = 0
        OverrideWrites = 0
        Failure = $failure
    }
    $errorMessage = $null
    try { Invoke-InputMethodScript -State $state } catch { $errorMessage = $_.Exception.Message }
    $expectedError = if ($failure -eq "LanguageList") { "*Language*list*" } else { "*Override*" }
    Assert-Test ($errorMessage -like $expectedError) "$failure failure was not surfaced: '$errorMessage'."
    Microsoft.PowerShell.Utility\Write-Host "[PASS] $failure failures are surfaced."
}

Microsoft.PowerShell.Utility\Write-Host "[PASS] Script parses in Windows PowerShell 5.1."
