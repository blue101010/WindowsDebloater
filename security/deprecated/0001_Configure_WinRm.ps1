<#
.SYNOPSIS
Configures WinRM on the local machine.

.DESCRIPTION
This script configures WinRM (Windows Remote Management) on the local machine. It enables the WinRM service and sets up the necessary firewall rules to allow remote management.

.PARAMETER None
This script does not accept any parameters.

.EXAMPLE
Configure-WinRm
This command configures WinRM on the local machine.

.NOTES
Author: Your Name
Date: Today's Date
#>

$title = "[0001_Configure_WinRm]"

try {
    # Configure WinRM
    winrm quickconfig -Force
}
catch {
    if ($_.Exception.Message -like "*network connection types on this machine is set to Public*") {
        # Change network profile to Private
        Write-Host "$title Network connection type is set to Public. Changing to Private..."
        Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | Set-NetConnectionProfile -NetworkCategory Private
        Write-Host "$title Network connection type has been changed to Private."
        # Retry WinRM configuration
        Write-Host "$title Retrying WinRM configuration..."
        winrm quickconfig -Force
        Write-Host "$title WinRM configuration completed."
    }
    else {
        Write-Host "$title An error occurred: $($_.Exception.Message)"
        throw $_
    }
}

# Install PSDesiredStateConfiguration module
Write-Host "$title (FORCE) Installing PSDesiredStateConfiguration module "
Install-Module -Name PSDesiredStateConfiguration -Force
Write-Host "$title PSDesiredStateConfiguration module installed."