# Disable password saving in Brave Browser
# This script modifies the Brave configuration to prevent password saving prompts.
# Close Brave and back up Preferences before running. Compatible with PowerShell 5.1.

    # Set the path to the Brave configuration file (change if needed)
    $BraveConfigPath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Preferences"

    # Check if the configuration file exists
    if (Test-Path -LiteralPath $BraveConfigPath -PathType Leaf -ErrorAction Stop) {
        # Read the existing configuration
        $BraveConfig = Get-Content -Raw -LiteralPath $BraveConfigPath -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

        # Initialize necessary objects if they don't exist
        if (-not $BraveConfig.profile) {
            $BraveConfig | Add-Member -MemberType NoteProperty -Name "profile" -Value ([PSCustomObject]@{})
        }
        
        if ($null -eq $BraveConfig.profile.PSObject.Properties["password_manager_enabled"]) {
            $BraveConfig.profile | Add-Member -MemberType NoteProperty -Name "password_manager_enabled" -Value $true
        }

        # Update the settings to disable password saving
        $BraveConfig.profile.password_manager_enabled = $false

        # Save the modified configuration back to the file
        $BraveConfig | ConvertTo-Json -Depth 100 -ErrorAction Stop | Set-Content -LiteralPath $BraveConfigPath -Encoding UTF8 -ErrorAction Stop

        Write-Host "[0381_Disable_Brave_save_passwords_offer] Password saving in Brave Browser has been disabled."
    } else {
        Write-Warning "[0381_Disable_Brave_save_passwords_offer] Brave Browser preferences file not found at: $BraveConfigPath. No changes made."
    }
