$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0175_Enable_controlled_folder_Access_enabled.ps1"

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-EnabledScript {
    param([hashtable]$State)

    function Set-MpPreference {
        param($EnableControlledFolderAccess, $ErrorAction)
        Assert-Test ($EnableControlledFolderAccess -eq "Enabled" -and $ErrorAction -eq "Stop") "Unexpected Defender write."
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
    @{ Name = "Enabled confirmed"; Preferences = @{ EnableControlledFolderAccess = 1 } },
    @{ Name = "AuditMode rejected"; Preferences = @{ EnableControlledFolderAccess = 2 }; Error = "*Verification failed:*" },
    @{ Name = "Disabled rejected"; Preferences = @{ EnableControlledFolderAccess = 0 }; Error = "*Verification failed:*" },
    @{ Name = "Missing status"; Preferences = @{}; Error = "*Verification failed:*" },
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
    try { Invoke-EnabledScript -State $state }
    catch { $failure = $_.Exception.Message }
    if ($case.Error) {
        Assert-Test ($failure -like $case.Error) "$($case.Name): unexpected error '$failure'."
        Assert-Test ($state.Messages.Count -eq 0) "$($case.Name): failure reported success."
    }
    else {
        Assert-Test ($null -eq $failure) "$($case.Name): unexpected error '$failure'."
        Assert-Test ($state.Messages.Count -eq 1 -and $state.Messages[0].Contains("[confirmed] Controlled Folder Access = Enabled (1)")) "Missing confirmed status."
    }
    $expectedReads = if ($case.Failure -eq "Write") { 0 } else { 1 }
    Assert-Test ($state.Writes -eq 1 -and $state.Reads -eq $expectedReads) "$($case.Name): unexpected operation counts."
    Write-Host "[PASS] $($case.Name)."
}
