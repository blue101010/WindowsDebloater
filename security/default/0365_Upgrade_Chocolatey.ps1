<#
.SYNOPSIS
    Upgrades Chocolatey package manager and optionally all installed packages.

.DESCRIPTION
    This script upgrades the Chocolatey package manager itself to the latest version.
    It can also optionally upgrade all installed packages.

.PARAMETER UpgradeAll
    If specified, upgrades all installed Chocolatey packages in addition to Chocolatey itself.

.EXAMPLE
    .\0365_Upgrade_Chocolatey.ps1
    Upgrades only Chocolatey itself.

.EXAMPLE
    .\0365_Upgrade_Chocolatey.ps1 -UpgradeAll
    Upgrades Chocolatey and all installed packages.

.NOTES
    Requires administrative privileges.
#>

param(
    [switch]$UpgradeAll
)

$title = "[0365_Upgrade_Chocolatey]"

# Check if Chocolatey is installed
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Error "$title Chocolatey is not installed. Please run 0364_get_chocolatey_iex.ps1 first."
    exit 1
}

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "$title You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    exit 1
}

# Display current version
Write-Host "$title Current Chocolatey version:" -ForegroundColor Cyan
choco -v

# Upgrade Chocolatey itself
Write-Host "`n$title Upgrading Chocolatey package manager..." -ForegroundColor Cyan
choco upgrade chocolatey -y

# Display new version
Write-Host "`n$title New Chocolatey version:" -ForegroundColor Cyan
choco -v

# Optionally upgrade all packages
if ($UpgradeAll) {
    Write-Host "`n$title Upgrading all installed packages..." -ForegroundColor Cyan
    choco upgrade all -y
    
    Write-Host "`n$title All packages have been upgraded." -ForegroundColor Green
} else {
    Write-Host "`n$title Chocolatey upgrade complete." -ForegroundColor Green
    Write-Host "$title To upgrade all packages, run: choco upgrade all -y" -ForegroundColor Gray
    Write-Host "$title Or run this script with -UpgradeAll parameter" -ForegroundColor Gray
}
