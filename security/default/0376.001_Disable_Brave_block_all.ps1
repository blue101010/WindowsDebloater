# ! Warning: This script is intended for use with the Brave browser only and to block ALL cookies, JavaScript, pop-ups, ads, and trackers. 
#Use with caution as it may affect the functionality of some websites.
# Modify the settings as needed to suit your requirements. !
# Close Brave before running. For another profile, pass -BravePrefsPath using
# the Profile Path shown in brave://version, followed by \Preferences.
[CmdletBinding()]
param(
    [string]$BravePrefsPath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Preferences"
)

# Check if the preferences file exists
if (Test-Path -LiteralPath $BravePrefsPath -PathType Leaf -ErrorAction Stop) {
    # Read the existing preferences
    $BravePrefs = Get-Content $BravePrefsPath -Raw | ConvertFrom-Json

    # Modify settings for enhanced privacy
    $BravePrefs.profile.default_content_setting_values = @{
        cookies = 2        # Block all cookies
        javascript = 2     # Block JavaScript
        popups = 2         # Block pop-ups
        ads = 2            # Block ads
        trackers = 2       # Block trackers
    }

    $BravePrefs.brave = @{
        ad_block = @{
            enabled = $true
            regional_lists = @()
            standard_lists = @(
                "easylist",
                "easyprivacy",
                "nocoin"
            )
        }
        shields = @{
            block_all_cookies = $true
            block_cross_site_cookies = $true
            block_third_party_storage = $true
            fingerprinting = 2  # Strict fingerprinting protection
            https_everywhere = @{
                enabled = $true
                mode = 1  # Upgrade connections to HTTPS
            }
            script_blocking = $true
        }
    }

    # Write the modified preferences back to the file
    $BravePrefs | ConvertTo-Json -Depth 10 | Set-Content $BravePrefsPath -Force

    Write-Output "Brave browser has been hardened successfully."
} else {
    Write-Warning "Brave preferences file not found: $BravePrefsPath. Run Brave once for this Windows user, or pass -BravePrefsPath for another profile. No changes made."
}
