<#
.SYNOPSIS
  Disables Microsoft Edge Startup Boost (for all users)
  and removes MicrosoftEdgeAutoLaunch_* entries from Run (current user).

.EXECUTION
  Run from a PowerShell console started as Administrator.
#>

param(
    [switch]$ChildRun,
    [string]$StatusFile
)

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    switch ($Level) {
        'SUCCESS' { $color = 'Green' }
        'WARN'    { $color = 'Yellow' }
        'ERROR'   { $color = 'Red' }
        default   { $color = 'Cyan' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Save-RunStatus {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Status,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    try {
        $Status | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding UTF8 -Force
    }
    catch {
        Write-Log -Level WARN -Message "Unable to write status file '$Path': $($_.Exception.Message)"
    }
}

$runStatus = @{
    Success = $true
    Elevated = $false
    PolicyConfigured = $false
    PolicyKeyCreated = $false
    RunKeyExists = $null
    RemovedEntries = 0
    NoMatchingRunEntries = $false
    ActionsCompleted = @()
    ActionsRemaining = @()
    Errors = @()
}

# Self-elevate when not running as Administrator (required for HKLM policy changes).
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $exitCode = 1

    Write-Log -Level WARN -Message "Administrator privileges are required. A UAC prompt will be shown in 3 seconds. Press Ctrl+C to cancel."
    Start-Sleep -Seconds 3

    $scriptPath = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($StatusFile)) {
        $StatusFile = Join-Path -Path $env:TEMP -ChildPath ("edge_startup_boost_status_{0}.json" -f [guid]::NewGuid().ToString())
    }

    $psArgs = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        "`"$scriptPath`""
        '-ChildRun'
        '-StatusFile'
        "`"$StatusFile`""
    )

    try {
        Write-Log -Message "Requesting elevation..."
        $elevatedProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs -Verb RunAs -PassThru -ErrorAction Stop
        Write-Log -Message "Elevation accepted. Waiting for elevated execution to finish..."
        $elevatedProcess.WaitForExit()

        if ($elevatedProcess.ExitCode -eq 0) {
            Write-Log -Level SUCCESS -Message "Elevated execution completed successfully."
        }
        else {
            Write-Log -Level ERROR -Message "Elevated execution completed with errors (exit code: $($elevatedProcess.ExitCode))."
        }

        $exitCode = $elevatedProcess.ExitCode

        if (Test-Path -Path $StatusFile) {
            try {
                $summary = Get-Content -Path $StatusFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

                Write-Log -Message "Summary from elevated execution:"

                if ($summary.ActionsCompleted.Count -gt 0) {
                    foreach ($item in $summary.ActionsCompleted) {
                        Write-Log -Level SUCCESS -Message "DONE: $item"
                    }
                }
                else {
                    Write-Log -Level WARN -Message "DONE: No configuration changes were applied."
                }

                if ($summary.ActionsRemaining.Count -gt 0) {
                    foreach ($item in $summary.ActionsRemaining) {
                        Write-Log -Level INFO -Message "REMAINING: $item"
                    }
                }

                if ($summary.Errors.Count -gt 0) {
                    foreach ($item in $summary.Errors) {
                        Write-Log -Level ERROR -Message "ERROR: $item"
                    }
                }
            }
            catch {
                Write-Log -Level WARN -Message "Could not parse elevated summary file '$StatusFile': $($_.Exception.Message)"
            }
            finally {
                Remove-Item -Path $StatusFile -Force -ErrorAction SilentlyContinue
            }
        }
        else {
            Write-Log -Level WARN -Message "No summary file was produced by the elevated run."
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Elevation request failed or was canceled: $($_.Exception.Message)"
    }

    exit $exitCode
}

$removedEntries = 0
$hadErrors = $false

$runStatus.Elevated = $true

Write-Log -Message "Starting: disable Microsoft Edge Startup Boost and clean Run entries."

# --- 1. Disable Startup Boost via HKLM policy (all users) ---

$edgePolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

try {
    if (-not (Test-Path $edgePolicyKey)) {
        Write-Log -Message "Edge policy key not found. Creating: $edgePolicyKey"
        New-Item -Path $edgePolicyKey -Force -ErrorAction Stop | Out-Null
        $runStatus.PolicyKeyCreated = $true
        $runStatus.ActionsCompleted += "Created Edge policy key in HKLM."
    }

    # StartupBoostEnabled = 0 -> Startup Boost disabled by policy
    New-ItemProperty `
        -Path $edgePolicyKey `
        -Name "StartupBoostEnabled" `
        -PropertyType DWord `
        -Value 0 `
        -ErrorAction Stop `
        -Force | Out-Null

    Write-Log -Level SUCCESS -Message "Startup Boost disabled via policy (StartupBoostEnabled = 0)."
    $runStatus.PolicyConfigured = $true
    $runStatus.ActionsCompleted += "Configured StartupBoostEnabled=0 in HKLM policy."
}
catch {
    $hadErrors = $true
    $errorMsg = "Failed to configure Edge policy (HKLM): $($_.Exception.Message)"
    $runStatus.Success = $false
    $runStatus.Errors += $errorMsg
    Write-Log -Level ERROR -Message $errorMsg
}

# --- 2. Remove MicrosoftEdgeAutoLaunch_* values from HKCU Run ---

$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

if (Test-Path $runKey) {
    $runStatus.RunKeyExists = $true
    try {
        $props = Get-ItemProperty -Path $runKey

        # Get all properties whose name starts with MicrosoftEdgeAutoLaunch_
        $edgeAutoLaunchProps = $props.PSObject.Properties |
            Where-Object { $_.Name -like "MicrosoftEdgeAutoLaunch_*" }

        if ($edgeAutoLaunchProps.Count -gt 0) {
            foreach ($prop in $edgeAutoLaunchProps) {
                $name = $prop.Name
                Write-Log -Message "Removing Run value: $name"
                Remove-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue
                $removedEntries++
            }
            Write-Log -Level SUCCESS -Message "Removed $removedEntries MicrosoftEdgeAutoLaunch_* entrie(s) from HKCU Run."
            $runStatus.ActionsCompleted += "Removed $removedEntries MicrosoftEdgeAutoLaunch_* entry(ies) from HKCU Run."
        }
        else {
            Write-Log -Message "No MicrosoftEdgeAutoLaunch_* entries found in HKCU Run."
            $runStatus.NoMatchingRunEntries = $true
            $runStatus.ActionsCompleted += "Checked HKCU Run (no MicrosoftEdgeAutoLaunch_* entries found)."
        }

        $runStatus.RemovedEntries = $removedEntries
    }
    catch {
        $hadErrors = $true
        $errorMsg = "Failed to clean HKCU Run: $($_.Exception.Message)"
        $runStatus.Success = $false
        $runStatus.Errors += $errorMsg
        Write-Log -Level ERROR -Message $errorMsg
    }
}
else {
    $runStatus.RunKeyExists = $false
    $runStatus.ActionsCompleted += "HKCU Run key does not exist for this user (nothing to clean)."
    Write-Log -Level WARN -Message "HKCU Run key does not exist for this user: $runKey"
}

$runStatus.ActionsRemaining += "Restart or sign out/sign in to ensure all policy-related effects are applied."

Save-RunStatus -Status $runStatus -Path $StatusFile

if ($hadErrors) {
    Write-Log -Level ERROR -Message "Completed with errors. Review the messages above."
    Write-Log -Message "A reboot or sign-out/sign-in may still be required for applied changes."
    exit 1
}
else {
    Write-Log -Level SUCCESS -Message "Completed successfully. A reboot or sign-out/sign-in may be required for all changes to take effect."
    exit 0
}