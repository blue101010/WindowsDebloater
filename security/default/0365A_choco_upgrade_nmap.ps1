<#
.SYNOPSIS
This script checks if Chocolatey and nmap are installed, and upgrades nmap if a newer version is available.

.DESCRIPTION
The script first checks if Chocolatey is installed. If not, it displays a message to install Chocolatey and exits.
Next, it checks if nmap is installed. If nmap is installed, it compares the installed version with the latest available version using Chocolatey. If a newer version is available, it upgrades nmap. If the installed version is already up to date, it displays a message indicating that nmap is up to date.
If nmap is not installed, it displays a message to install nmap and proceeds to install it using Chocolatey.
At the end, it provides a link to the nmap download page.

.PARAMETER None
This script does not accept any parameters.

.EXAMPLE
.\0365_choco_upgrade_nmap.ps1
Runs the script to check and upgrade nmap if necessary.

.NOTES
Author: [Your Name]
Date: [Current Date]
Version: 1.0
#>

# Check if Chocolatey is installed
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
  Write-Output "[0365_choco_upgrade_nmap] Chocolatey is not installed. Please install Chocolatey first."
  exit
}

# Check if nmap is installed
$installedNmap = choco list --local-only nmap -r
if ($installedNmap) {
  # Get the installed version
  $installedVersion = $installedNmap.Split('|')[1]

  # Get the latest available version
  $latestVersion = (choco list nmap -r).Split('|')[1]

  # Compare the versions
  if ($installedVersion -lt $latestVersion) {
    # Upgrade nmap
    choco upgrade nmap -y
  }
  else {
    Write-Output "[0365A_choco_upgrade_nmap] nmap is up to date with latest version"
  }
}
else {
  Write-Output "[0365A_choco_upgrade_nmap] nmap is not installed. Let's install nmap first."
  choco install nmap -y
}

# Link to nmap download page
#https://nmap.org/download
