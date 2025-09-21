<#
.SYNOPSIS
    Disables Microsoft 365 advertisements in Windows Settings Home.
.DESCRIPTION
    MS 365 ads in Windows Settings refer to promotional messages that encourage users to start or 
    upgrade to a Microsoft 365 subscription, often appearing in the Windows Settings Home page or 
    system tabs even if the user doesn't want or need them. These ads are considered intrusive by 
    many, as they persistently appear across different areas of Windows, urge users to make purchases, 
    and cannot be easily dismissed or permanently removed via standard options.
    
    This script addresses this annoyance by modifying the Windows registry to set the 
    DisableConsumerAccountStateContent value to 1 under the CloudContent policies, effectively 
    disabling these promotional messages throughout the Windows Settings interface.
.NOTES
    Requires administrative privileges to modify the registry.
#>

$title = "[0436_Disable_Settings_365_Ads]"

# Path to the CloudContent policies registry key
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$registryName = "DisableConsumerAccountStateContent"
$targetValue = 1

Write-Host "$title Checking MS 365 ads status in Settings Home..."

try {
    # Ensure the registry path exists
    if (-not (Test-Path $registryPath)) {
        Write-Host "$title Creating registry path: $registryPath"
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value of the setting
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue).$registryName

    Write-Host "$title Current value: $currentValue"
    Write-Host "$title Target value: $targetValue (1 = Disabled, 0 = Enabled)"

    # Set the policy only if it's not already disabled
    if ($currentValue -ne $targetValue) {
        Write-Host "$title Setting DisableConsumerAccountStateContent to $targetValue..."
        Set-ItemProperty -Path $registryPath -Name $registryName -Value $targetValue -Type DWord
        
        # Verify the change was applied
        $verifyValue = (Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue).$registryName
        if ($verifyValue -eq $targetValue) {
            Write-Host "$title SUCCESS: MS 365 ads in Settings Home have been DISABLED." -ForegroundColor Green
        } else {
            Write-Host "$title ERROR: Failed to set the registry value." -ForegroundColor Red
        }
    } else {
        Write-Host "$title MS 365 ads in Settings Home are already DISABLED." -ForegroundColor Green
    }
}
catch {
    Write-Host "$title ERROR: Failed to modify registry - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "$title Registry path: $registryPath"
Write-Host "$title Registry value: $registryName = $targetValue"

#; Disable MS 365 Ads in Settings Home
#[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
#"DisableConsumerAccountStateContent"=dword:00000001