$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0193_Enable_AttackSurfaceReductionRules_Block_Process_Injection.ps1"
$expectedId = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-ASRScript {
    param([hashtable]$State)

    function Add-MpPreference {
        param($AttackSurfaceReductionRules_Ids, $AttackSurfaceReductionRules_Actions, $ErrorAction)
        Assert-Test ($AttackSurfaceReductionRules_Ids -eq $expectedId -and $AttackSurfaceReductionRules_Actions -eq "Enabled" -and $ErrorAction -eq "Stop") "Unexpected ASR write."
        $State.Writes++
        if ($State.Failure -eq "Write") { throw "Defender write denied." }
    }

    function Get-MpPreference {
        param($ErrorAction)
        Assert-Test ($ErrorAction -eq "Stop") "Verification must stop on errors."
        $State.Reads++
        if ($State.Failure -eq "Read") { throw "Defender read failed." }
        return [pscustomobject]$State.Preferences
    }

    function Write-Host {
        param([string]$Object)
        [void]$State.Messages.Add($Object)
    }

    & $scriptPath
}

foreach ($case in @(
    @{ Name = "Enabled confirmed"; Preferences = @{ AttackSurfaceReductionRules_Ids = $expectedId; AttackSurfaceReductionRules_Actions = 1 } },
    @{ Name = "Correct action among other rules"; Preferences = @{ AttackSurfaceReductionRules_Ids = @("other-rule", $expectedId.ToLower()); AttackSurfaceReductionRules_Actions = @(2, 1) } },
    @{ Name = "Wrong action"; Preferences = @{ AttackSurfaceReductionRules_Ids = $expectedId; AttackSurfaceReductionRules_Actions = 2 }; Error = "*Verification failed:*" },
    @{ Name = "Missing rule"; Preferences = @{ AttackSurfaceReductionRules_Ids = "other-rule"; AttackSurfaceReductionRules_Actions = 1 }; Error = "*Verification failed:*" },
    @{ Name = "Empty preferences"; Preferences = @{}; Error = "*Verification failed:*" },
    @{ Name = "Mismatched arrays"; Preferences = @{ AttackSurfaceReductionRules_Ids = @($expectedId, "other-rule"); AttackSurfaceReductionRules_Actions = 1 }; Error = "*Verification failed:*" },
    @{ Name = "Write failure"; Preferences = @{}; Failure = "Write"; Error = "Defender write denied." },
    @{ Name = "Read failure"; Preferences = @{}; Failure = "Read"; Error = "Defender read failed." }
)) {
    $state = @{
        Preferences = $case.Preferences
        Failure = $case.Failure
        Writes = 0
        Reads = 0
        Messages = New-Object 'System.Collections.Generic.List[string]'
    }
    $failure = $null
    try { Invoke-ASRScript -State $state }
    catch { $failure = $_.Exception.Message }
    if ($case.Error) {
        Assert-Test ($failure -like $case.Error) "$($case.Name): unexpected error '$failure'."
        Assert-Test ($state.Messages.Count -eq 0) "$($case.Name): failure reported success."
    }
    else {
        Assert-Test ($null -eq $failure) "$($case.Name): unexpected error '$failure'."
        Assert-Test ($state.Messages.Count -eq 1 -and $state.Messages[0].Contains("[confirmed]") -and $state.Messages[0].Contains("$expectedId) = Enabled (1)")) "Missing confirmed rule status."
    }
    $expectedReads = if ($case.Failure -eq "Write") { 0 } else { 1 }
    Assert-Test ($state.Writes -eq 1 -and $state.Reads -eq $expectedReads) "$($case.Name): unexpected operation counts."
    Write-Host "[PASS] $($case.Name)."
}
