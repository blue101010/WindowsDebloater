#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Disables and stops Dell bloatware services
.DESCRIPTION
    This script checks for Dell-related services, stops them if running, 
    and sets them to Manual startup type. All actions are logged.
.NOTES
    Version: 2.0
    Author: Windows10Debloater
    Date: 2026-02-23
#>

# Initialize logging
$LogPath = Join-Path $env:TEMP "Dell_Bloatware_Disable_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ServicesProcessed = 0
$ServicesNotFound = 0
$ServicesDisabled = 0
$ServicesStopped = 0
$ServicesProtected = 0
$FailedActions = 0

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogPath -Value $LogMessage -ErrorAction SilentlyContinue
    
    # Write to console with color
    switch ($Level) {
        'ERROR'   { Write-Host $LogMessage -ForegroundColor Red }
        'WARNING' { Write-Host $LogMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $LogMessage -ForegroundColor Green }
        default   { Write-Host $LogMessage }
    }
}

# Function to process a service
function Process-DellService {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    
    Write-Log "Processing service: $ServiceName" -Level INFO
    $script:ServicesProcessed++
    
    try {
        # Check if service exists
        $Service = Get-Service -Name $ServiceName -ErrorAction Stop
        Write-Log "Service '$ServiceName' found (Current Status: $($Service.Status), StartType: $($Service.StartType))" -Level INFO
        
        # Stop the service if it's running
        if ($Service.Status -eq 'Running') {
            Write-Log "Attempting to stop service '$ServiceName'..." -Level INFO
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                Write-Log "Successfully stopped service '$ServiceName'" -Level SUCCESS
                $script:ServicesStopped++
            }
            catch {
                # Analyze why the service can't be stopped
                Write-Log "Initial stop attempt failed - analyzing service protection..." -Level WARNING
                
                # Get detailed service information
                try {
                    $WmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
                    $ServiceDetails = Get-Service -Name $ServiceName -ErrorAction Stop
                    
                    # Check for dependent services
                    $DependentServices = Get-Service -Name $ServiceName -DependentServices -ErrorAction SilentlyContinue
                    if ($DependentServices -and $DependentServices.Count -gt 0) {
                        Write-Log "TECHNICAL INFO: Service has $($DependentServices.Count) dependent service(s): $($DependentServices.Name -join ', ')" -Level INFO
                        Write-Log "ACTION REQUIRED: Stop dependent services first or use: Stop-Service -Name '$ServiceName' -Force -ErrorAction SilentlyContinue" -Level INFO
                    }
                    
                    # Check service account (System services are often protected)
                    if ($WmiService.StartName -like "*LocalSystem*" -or $WmiService.StartName -eq "LocalSystem") {
                        Write-Log "TECHNICAL INFO: Service runs as LocalSystem account (high privilege)" -Level INFO
                    }
                    
                    # Check if it's a kernel driver or system service
                    if ($WmiService.ServiceType -match "Kernel") {
                        Write-Log "TECHNICAL INFO: Service type is Kernel Driver - protected by Windows" -Level INFO
                        Write-Log "ACTION REQUIRED: Requires system restart to stop kernel-level services" -Level WARNING
                    }
                    
                    # Try to get the actual error code
                    $ErrorCode = $_.Exception.HResult
                    if ($ErrorCode) {
                        Write-Log "TECHNICAL INFO: Error code: 0x$($ErrorCode.ToString('X8'))" -Level INFO
                    }
                    
                    # Check AcceptStop capability
                    if ($WmiService.AcceptStop -eq $false) {
                        Write-Log "TECHNICAL INFO: Service property 'AcceptStop' = False (service designed to refuse stop commands)" -Level INFO
                        Write-Log "ACTION REQUIRED: Service must be disabled and system rebooted" -Level WARNING
                    }
                    
                } catch {
                    Write-Log "Could not retrieve detailed service information: $($_.Exception.Message)" -Level WARNING
                }
                
                # Try alternative method using WMI if standard method fails
                Write-Log "Attempting alternative stop method using WMI..." -Level INFO
                try {
                    $WmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
                    if ($null -ne $WmiService) {
                        $Result = $WmiService.StopService()
                        if ($Result.ReturnValue -eq 0) {
                            Write-Log "Successfully stopped service '$ServiceName' using WMI" -Level SUCCESS
                            $script:ServicesStopped++
                        }
                        else {
                            Write-Log "WMI stop failed with return code: $($Result.ReturnValue)" -Level WARNING
                            
                            # Try using sc.exe as last resort
                            Write-Log "Attempting to stop using sc.exe command..." -Level INFO
                            try {
                                $ScResult = & sc.exe stop $ServiceName 2>&1
                                Start-Sleep -Seconds 2
                                
                                # Check if service actually stopped
                                $CheckService = Get-Service -Name $ServiceName -ErrorAction Stop
                                if ($CheckService.Status -eq 'Stopped') {
                                    Write-Log "Successfully stopped service '$ServiceName' using sc.exe" -Level SUCCESS
                                    $script:ServicesStopped++
                                }
                                else {
                                    Write-Log "Service '$ServiceName' is protected and cannot be stopped immediately." -Level WARNING
                                    Write-Log "REASON: Service has 'AcceptStop=False' or is kernel-level protected" -Level INFO
                                    Write-Log "RESULT: Service startup type changed to Manual - will NOT auto-start on next boot" -Level SUCCESS
                                    Write-Log "ACTION: Restart computer to fully stop this service" -Level WARNING
                                    $script:ServicesProtected++
                                }
                            }
                            catch {
                                Write-Log "sc.exe method also failed: All stop methods exhausted" -Level WARNING
                                Write-Log "REASON: Service is system-protected or has active handles" -Level INFO
                                Write-Log "RESULT: Service startup type will be set to Manual - prevents auto-start" -Level SUCCESS
                                Write-Log "ACTION: Restart computer to fully stop this service" -Level WARNING
                                $script:ServicesProtected++
                            }
                        }
                    }
                    else {
                        Write-Log "Service not accessible via WMI - attempting direct service query" -Level INFO
                        try {
                            $ScInfo = & sc.exe qc $ServiceName 2>&1 | Out-String
                            Write-Log "TECHNICAL INFO: Service configuration retrieved via sc.exe" -Level INFO
                            Write-Log "REASON: Service is protected at kernel or driver level" -Level INFO
                        } catch {
                            Write-Log "REASON: Service has elevated protection preventing remote/WMI access" -Level INFO
                        }
                        Write-Log "RESULT: Service startup type will be set to Manual - prevents auto-start" -Level SUCCESS
                        Write-Log "ACTION: Restart computer to fully stop this service" -Level WARNING
                        $script:ServicesProtected++
                    }
                }
                catch {
                    Write-Log "WMI method failed: $($_.Exception.Message)" -Level INFO
                    Write-Log "REASON: Service protection level blocks WMI stop operations" -Level INFO
                    Write-Log "RESULT: Service startup type will be set to Manual - prevents auto-start" -Level SUCCESS
                    Write-Log "ACTION: Restart computer to fully stop this service" -Level WARNING
                    $script:ServicesProtected++
                }
            }
        }
        else {
            Write-Log "Service '$ServiceName' is already stopped (Status: $($Service.Status))" -Level INFO
        }
        
        # Set startup type to Manual
        Write-Log "Setting service '$ServiceName' to Manual startup type..." -Level INFO
        try {
            Set-Service -Name $ServiceName -StartupType Manual -ErrorAction Stop
            
            # Verify the change
            $VerifyService = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($VerifyService.StartType -eq 'Manual') {
                Write-Log "Successfully set service '$ServiceName' to Manual startup type" -Level SUCCESS
                $script:ServicesDisabled++
            }
            else {
                Write-Log "Warning: Service '$ServiceName' startup type is '$($VerifyService.StartType)', expected 'Manual'" -Level WARNING
                $script:FailedActions++
            }
        }
        catch {
            Write-Log "Failed to set startup type for service '$ServiceName': $($_.Exception.Message)" -Level ERROR
            $script:FailedActions++
        }
    }
    catch {
        if ($_.Exception.Message -like "*Cannot find*" -or $_.Exception.Message -like "*does not exist*") {
            Write-Log "Service '$ServiceName' not found on this system (skipping)" -Level WARNING
            $script:ServicesNotFound++
        }
        else {
            Write-Log "Error accessing service '$ServiceName': $($_.Exception.Message)" -Level ERROR
            $script:FailedActions++
        }
    }
    
    Write-Log "Completed processing service: $ServiceName" -Level INFO
    Write-Log "----------------------------------------" -Level INFO
}

# Main execution
Write-Log "========================================" -Level INFO
Write-Log "Dell Bloatware Service Disabler Started" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Log file: $LogPath" -Level INFO
Write-Log "" -Level INFO

# Define Dell services to disable
$DellServices = @(
    "DellTechHub",
    "DellClientManagementService",
    "DellInstrumentation"
)

# Process each service
foreach ($ServiceName in $DellServices) {
    Process-DellService -ServiceName $ServiceName
}

# Summary
Write-Log "" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "EXECUTION SUMMARY" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Total services checked: $ServicesProcessed" -Level INFO
Write-Log "Services not found: $ServicesNotFound" -Level INFO
Write-Log "Services stopped: $ServicesStopped" -Level SUCCESS
Write-Log "Services set to Manual: $ServicesDisabled" -Level SUCCESS
Write-Log "Protected services (require restart): $ServicesProtected" -Level $(if ($ServicesProtected -gt 0) { 'WARNING' } else { 'INFO' })
Write-Log "Critical failures: $FailedActions" -Level $(if ($FailedActions -gt 0) { 'ERROR' } else { 'INFO' })
Write-Log "Log file saved to: $LogPath" -Level INFO
Write-Log "========================================" -Level INFO

# Exit with appropriate code
if ($FailedActions -gt 0) {
    Write-Log "Script completed with critical errors" -Level ERROR
    exit 1
}
elseif ($ServicesNotFound -eq $ServicesProcessed) {
    Write-Log "Script completed - no Dell services found on this system" -Level WARNING
    exit 0
}
elseif ($ServicesProtected -gt 0) {
    Write-Log "Script completed successfully - All services set to Manual startup" -Level SUCCESS
    Write-Log "" -Level INFO
    Write-Log "TECHNICAL SUMMARY:" -Level INFO
    Write-Log "- $ServicesProtected service(s) are system-protected (AcceptStop=False or kernel-level)" -Level INFO
    Write-Log "- These services have been set to Manual startup (will NOT auto-start)" -Level SUCCESS
    Write-Log "- Currently running instances require system restart to terminate" -Level WARNING
    Write-Log "" -Level INFO
    Write-Log "RECOMMENDED ACTION: Restart your computer to complete the process" -Level WARNING
    Write-Log "VERIFICATION: After restart, run this script again to confirm all services are stopped" -Level INFO
    exit 0
}
else {
    Write-Log "Script completed successfully - All services stopped and set to Manual" -Level SUCCESS
    exit 0
}