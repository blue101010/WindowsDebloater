<#
.SYNOPSIS
Disables WinRM on the local machine.

.DESCRIPTION
This script disables WinRM (Windows Remote Management) on the local machine. It stops the WinRM service,
sets it to disabled startup, and blocks related firewall rules to prevent remote management.

.PARAMETER None
This script does not accept any parameters.

.EXAMPLE
Disable-WinRm
This command disables WinRM on the local machine.

.NOTES
Author: Your Name
Date: Today's Date
#>

$title = "[0001_Disable_WinRm]"

# Function to check if running with administrator privileges
function Test-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

# Check for admin rights
if (-not (Test-Administrator)) {
    Write-Host "$title This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
    exit 1
}

# Get the current status of WinRM service
$winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue

if ($null -eq $winrmService) {
    Write-Host "$title WinRM service not found. No action needed."
    exit 0
} 
elseif ($winrmService.Status -eq 'Stopped' -and $winrmService.StartType -eq 'Disabled') {
    Write-Host "$title WinRM service is already disabled. No action needed."
    
    # Block WinRM firewall rules as an additional precaution
    Write-Host "$title Ensuring WinRM firewall rules are blocked..."
    Get-NetFirewallRule -DisplayName "Windows Remote Management*" -ErrorAction SilentlyContinue | 
        Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
    Write-Host "$title Done."
    exit 0
}
else {
    try {
        # Disable firewall rules first
        Write-Host "$title Blocking WinRM firewall rules..."
        Get-NetFirewallRule -DisplayName "Windows Remote Management*" -ErrorAction SilentlyContinue | 
            Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
        Write-Host "$title WinRM firewall rules blocked."
        
        # Try to disable PS Remoting if WinRM is running
        if ($winrmService.Status -eq 'Running') {
            try {
                Write-Host "$title Attempting to disable PowerShell remoting..."
                Disable-PSRemoting -Force -ErrorAction SilentlyContinue
                Write-Host "$title PowerShell remoting disabled."
            }
            catch {
                Write-Host "$title Note: Could not disable PS Remoting completely. Will proceed with service disabling." -ForegroundColor Yellow
            }
            
            # Try to remove WinRM listeners if service is running
            try {
                Write-Host "$title Removing WinRM listeners..."
                winrm delete winrm/config/listener?Address=*+Transport=HTTP -ErrorAction SilentlyContinue
                winrm delete winrm/config/listener?Address=*+Transport=HTTPS -ErrorAction SilentlyContinue
                Write-Host "$title WinRM listeners removed."
            }
            catch {
                Write-Host "$title Note: Could not remove all WinRM listeners. Will proceed with service disabling." -ForegroundColor Yellow
            }
        }
        
        # Stop the WinRM service if it's running
        if ($winrmService.Status -eq 'Running') {
            Write-Host "$title Stopping WinRM service..."
            Stop-Service -Name WinRM -Force -ErrorAction Stop
            Write-Host "$title WinRM service stopped."
        }

        # Disable the WinRM service
        Write-Host "$title Disabling WinRM service..."
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop
        Write-Host "$title WinRM service disabled."
        
        # Reset LocalAccountTokenFilterPolicy to default (0)
        try {
            Write-Host "$title Resetting LocalAccountTokenFilterPolicy..."
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (Test-Path $regPath) {
                if (Get-ItemProperty -Path $regPath -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue) {
                    Set-ItemProperty -Path $regPath -Name "LocalAccountTokenFilterPolicy" -Value 0
                    Write-Host "$title LocalAccountTokenFilterPolicy reset to 0."
                }
            }
        }
        catch {
            Write-Host "$title Note: Could not reset LocalAccountTokenFilterPolicy. Manual check recommended." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "$title An error occurred while disabling WinRM: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "$title WinRM disabling failed. Please check the service status manually." -ForegroundColor Red
        exit 1
    }
}

Write-Host "$title WinRM has been successfully disabled." -ForegroundColor Green