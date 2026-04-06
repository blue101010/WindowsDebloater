<#
.SYNOPSIS
Manage Windows power throttling behavior for VMware Workstation (vmware-vmx.exe).

.DESCRIPTION
Some Windows hosts may throttle VMware VM processes, which can cause unstable or poor VM performance.
This script applies or reverts a power throttling rule for the VMware executable:
- disable: prevents power throttling for vmware-vmx.exe
- reset: removes the custom rule and returns to default behavior

.PARAMETER Action
Required action argument.
Accepted forms:
- --disable, -disable, disable
- --reset, -reset, reset

.EXAMPLE
.\0457_Manage_Windows_powerthrottling_vmware.ps1 --disable

.EXAMPLE
.\0457_Manage_Windows_powerthrottling_vmware.ps1 --reset

.NOTES
If not run as Administrator, the script can prompt for UAC elevation and relaunch itself.
#>

param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Action
)

$vmwarePath = "C:\Program Files (x86)\VMWare\VMWare Workstation\x64\vmware-vmx.exe"

# Normalize supported inputs so both --disable/--reset and -disable/-reset work.
$normalizedAction = $Action.Trim().ToLowerInvariant()
switch ($normalizedAction) {
    '--disable' { $normalizedAction = 'disable' }
    '-disable'  { $normalizedAction = 'disable' }
    'disable'   { $normalizedAction = 'disable' }
    '--reset'   { $normalizedAction = 'reset' }
    '-reset'    { $normalizedAction = 'reset' }
    'reset'     { $normalizedAction = 'reset' }
    default {
        Write-Error "Invalid action '$Action'. Use one of: --disable, --reset, -disable, -reset"
        exit 1
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator. powercfg requires elevation." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    $answer = Read-Host "Re-run with elevated privileges (UAC)? [y/N]"
    if ($answer -match '^[Yy]$') {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`" -Action $normalizedAction" -Verb RunAs
    }
    exit
}

switch ($normalizedAction) {
    'disable' {
        Write-Host "Disabling power throttling for VMware..."
        powercfg /powerthrottling disable /path $vmwarePath
    }
    'reset' {
        Write-Host "Resetting power throttling for VMware..."
        powercfg /powerthrottling reset /path $vmwarePath
    }
}

Start-Sleep -Seconds 3
Read-Host "Done. Press Enter to exit"