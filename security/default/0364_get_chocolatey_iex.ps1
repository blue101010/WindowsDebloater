<#
.SYNOPSIS
Installs Chocolatey package manager if it is not already installed.

.DESCRIPTION
This script checks if Chocolatey is already installed on the system. If not, it downloads 
the Chocolatey installation script to a temporary file for user inspection before execution.
This approach allows users to review the script contents for security purposes before 
allowing it to run with elevated privileges.

.PARAMETER None

.EXAMPLE
.\0364_get_chocolatey_iex.ps1

This example runs the script to install Chocolatey.

.NOTES
Author: [Your Name]
Date: [Current Date]
Version: 2.0
Security: Downloads script to temporary file for inspection before execution
#>

$title = "[0364_get_chocolatey_iex]"

# Check if Chocolatey is already installed
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Output "$title Chocolatey is already installed at '$((Get-Command choco).Source)'. Use 'choco' to manage packages."
    exit 0
}

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "$title You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    exit 1
}

# Set execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Ensure use of TLS1.2 or higher
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Download to temporary file
$chocolateyUrl = 'https://community.chocolatey.org/install.ps1'
$tempFile = Join-Path $env:TEMP "chocolatey-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').ps1"

Write-Host "$title Downloading Chocolatey installer..." -ForegroundColor Cyan
Write-Host "$title Source: $chocolateyUrl" -ForegroundColor Gray
Write-Host "$title Destination: $tempFile" -ForegroundColor Gray

try {
    # Download with error handling
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($chocolateyUrl, $tempFile)
    
    # Verify download
    if (-not (Test-Path $tempFile)) {
        throw "Downloaded file not found at $tempFile"
    }
    
    $fileSize = (Get-Item $tempFile).Length
    Write-Host "$title Download complete. File size: $fileSize bytes" -ForegroundColor Green
    
    # Security prompt
    Write-Host "`n$title SECURITY NOTICE:" -ForegroundColor Yellow
    Write-Warning "You are about to execute a script downloaded from the internet."
    Write-Host "Location: $tempFile" -ForegroundColor Cyan
    Write-Host "`nPlease review the downloaded script before proceeding." -ForegroundColor Yellow
    Write-Host "You can open it with: notepad `"$tempFile`"" -ForegroundColor Gray
    
    # User confirmation
    Write-Host "`n" -NoNewline
    $continue = Read-Host "Continue with installation? (yes/no)"
    
    if ($continue -ne 'yes') {
        Write-Host "$title Installation cancelled by user." -ForegroundColor Yellow
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        exit 0
    }
    
    # Execute the downloaded file
    Write-Host "`n$title Executing Chocolatey installer..." -ForegroundColor Cyan
    & $tempFile
    
    # Verify installation
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "`n$title Chocolatey installed successfully!" -ForegroundColor Green
        choco -v
    } else {
        Write-Warning "$title Chocolatey installation completed but 'choco' command not found. You may need to restart your shell."
    }
    
} catch {
    Write-Error "$title Download or installation failed: $($_.Exception.Message)"
    exit 1
} finally {
    # Cleanup
    if (Test-Path $tempFile) {
        Write-Host "$title Cleaning up temporary file..." -ForegroundColor Gray
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}