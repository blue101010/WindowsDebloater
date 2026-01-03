<#
.SYNOPSIS
    Blocks payment and billing features in Perplexity Comet browser.

.DESCRIPTION
    This script prevents payment/billing features from loading in Comet (Perplexity's Chromium-based browser)
    by creating managed policies and modifying user preferences. It blocks access to payment-related URLs
    and disables payment handlers.

.NOTES
    - Comet should be closed before running this script
    - Creates a backup of existing preferences
    - Requires write access to the Comet User Data directory
#>

param(
    [switch]$Force
)

$title = "[0441_Block_Comet_Payment]"

function Test-CometReadiness {
    param(
        [string]$Title,
        [switch]$Force
    )

    $issues = @()

    $cometProcess = Get-Process -Name "comet" -ErrorAction SilentlyContinue
    if ($cometProcess) {
        $pids = ($cometProcess | Select-Object -ExpandProperty Id) -join ', '
        $issues += "Comet is running (PID(s): $pids)."
    }

    if (-not $issues) {
        Write-Host "$Title Environment check passed. Proceeding with configuration." -ForegroundColor Green
        return $true
    }

    Write-Host "$Title Environment check detected issues:" -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }

    if ($Force) {
        Write-Host "$Title Force flag supplied. Continuing despite warnings." -ForegroundColor Yellow
        return $true
    }

    Write-Host "$Title Aborting configuration. Resolve the issues above or rerun with -Force to override." -ForegroundColor Red
    return $false
}

function Write-CheckResult {
    param(
        [string]$Label,
        [bool]$State,
        [string]$Message
    )

    if ($State) {
        Write-Host ("  {0,-14}: OK" -f $Label) -ForegroundColor Green
    } else {
        Write-Host ("  {0,-14}: Needs attention" -f $Label) -ForegroundColor Yellow
        if ($Message) {
            Write-Host ("      -> {0}" -f $Message) -ForegroundColor DarkGray
        }
    }
}

function Get-NestedValue {
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        [string[]]$Path
    )

    $current = $Object
    foreach ($segment in $Path) {
        if (-not $current) { return $null }
        $property = $current.PSObject.Properties.Match($segment)
        if (-not $property) { return $null }
        $current = $property.Value
    }
    return $current
}

function Test-CometConfiguration {
    param(
        [string]$CometUserData
    )

    $policyFile = Join-Path $CometUserData 'Policies\managed_policies.json'
    $prefsPath = Join-Path $CometUserData 'Default\Preferences'
    $localStatePath = Join-Path $CometUserData 'Local State'

    $requiredPolicyUrls = @(
        'comet://settings/payments*',
        'https://perplexity.ai/payment*'
    )

    $result = [ordered]@{
        PolicyOk = $false
        PrefsOk = $false
        LocalStateOk = $false
        PolicyMessage = ''
        PrefsMessage = ''
        LocalStateMessage = ''
    }

    if (Test-Path $policyFile) {
        try {
            $policy = Get-Content $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $urlList = @($policy.BlockedUrlPatterns)
            $missingUrls = $requiredPolicyUrls | Where-Object { $urlList -notcontains $_ }
            $flagsOk = ($policy.PaymentMethodQueryEnabled -eq $false) -and ($policy.AutofillCreditCardEnabled -eq $false)
            if (-not $missingUrls -and $flagsOk) {
                $result.PolicyOk = $true
            } else {
                $result.PolicyMessage = if ($missingUrls) { "Missing blocked URLs: $($missingUrls -join ', ')" } else { 'Payment blocking flags not set.' }
            }
        }
        catch {
            $result.PolicyMessage = "Unable to parse managed_policies.json: $($_.Exception.Message)"
        }
    } else {
        $result.PolicyMessage = 'Managed policies file not found.'
    }

    if (Test-Path $prefsPath) {
        try {
            $prefs = Get-Content $prefsPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $creditDisabled = (Get-NestedValue -Object $prefs -Path @('autofill','credit_card_enabled')) -eq $false
            $profileDisabled = (Get-NestedValue -Object $prefs -Path @('autofill','profile_enabled')) -eq $false
            $perplexityBlocked = (Get-NestedValue -Object $prefs -Path @('profile','content_settings','exceptions','payment_handler','[*.]perplexity.ai,*','setting')) -eq 2
            $settingsBlocked = (Get-NestedValue -Object $prefs -Path @('profile','content_settings','exceptions','payment_handler','comet://settings/*,*','setting')) -eq 2
            if ($creditDisabled -and $profileDisabled -and $perplexityBlocked -and $settingsBlocked) {
                $result.PrefsOk = $true
            } else {
                $result.PrefsMessage = 'Autofill or payment handler settings are not fully disabled.'
            }
        }
        catch {
            $result.PrefsMessage = "Unable to parse Preferences: $($_.Exception.Message)"
        }
    } else {
        $result.PrefsMessage = 'Preferences file not found (launch Comet once).'
    }

    if (Test-Path $localStatePath) {
        try {
            $localState = Get-Content $localStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $paymentsFlag = Get-NestedValue -Object $localState -Path @('browser','payments_integration_enabled')
            if ($paymentsFlag -eq $false) {
                $result.LocalStateOk = $true
            } else {
                $result.LocalStateMessage = 'payments_integration_enabled is not disabled.'
            }
        }
        catch {
            $result.LocalStateMessage = "Unable to parse Local State: $($_.Exception.Message)"
        }
    } else {
        $result.LocalStateMessage = 'Local State file not found.'
    }

    $result.IsCompliant = $result.PolicyOk -and $result.PrefsOk -and $result.LocalStateOk
    return [pscustomobject]$result
}

# Define Comet paths
$cometUserData = "$env:LOCALAPPDATA\Perplexity\Comet\User Data"
$cometExe = "$env:LOCALAPPDATA\Perplexity\Comet\Application\comet.exe"

Write-Host "$title Checking for Comet installation..." -ForegroundColor Cyan

# Check if Comet is installed
if (-not (Test-Path $cometUserData)) {
    Write-Host "$title Comet User Data folder not found at: $cometUserData" -ForegroundColor Yellow
    Write-Host "$title Is Perplexity Comet installed?" -ForegroundColor Yellow
    exit 0
}

Write-Host "$title Found Comet User Data at: $cometUserData" -ForegroundColor Green

$configStatus = Test-CometConfiguration -CometUserData $cometUserData

Write-Host "`n$title Configuration status:" -ForegroundColor Cyan
Write-CheckResult -Label 'Policies' -State $configStatus.PolicyOk -Message $configStatus.PolicyMessage
Write-CheckResult -Label 'Preferences' -State $configStatus.PrefsOk -Message $configStatus.PrefsMessage
Write-CheckResult -Label 'Local State' -State $configStatus.LocalStateOk -Message $configStatus.LocalStateMessage

if ($configStatus.IsCompliant) {
    Write-Host "`n$title All payment-blocking controls are already enforced. No changes required." -ForegroundColor Green
    exit 0
}

Write-Host "`n$title Configuration drift detected. Remediation will be applied." -ForegroundColor Yellow

if (-not (Test-CometReadiness -Title $title -Force:$Force)) {
    exit 1
}

try {
    # 1. Create Policies folder and managed policies
    Write-Host "`n$title Creating managed policies..." -ForegroundColor Cyan
    $policiesPath = "$cometUserData\Policies"
    if (-not (Test-Path $policiesPath)) {
        New-Item -Path $policiesPath -ItemType Directory -Force | Out-Null
        Write-Host "$title Created policies directory: $policiesPath" -ForegroundColor Green
    }
    
    # Create comprehensive managed policies JSON file
    $managedPolicies = @{
        "BlockedUrlPatterns" = @(
            "comet://settings/payments*",
            "comet://settings/billing*",
            "comet://settings/cards*",
            "comet://settings/autofill/creditCards*",
            "comet://payment/*",
            "comet://checkout/*",
            "https://*.perplexity.ai/payment*",
            "https://*.perplexity.ai/billing*",
            "https://*.perplexity.ai/checkout*",
            "https://*.perplexity.ai/subscribe*",
            "https://*.perplexity.ai/upgrade*",
            "https://perplexity.ai/payment*",
            "https://perplexity.ai/billing*",
            "https://perplexity.ai/checkout*",
            "https://perplexity.ai/subscribe*",
            "https://perplexity.ai/upgrade*"
        )
        "BlockThirdPartyCookies" = $true
        "PaymentMethodQueryEnabled" = $false
        "AutofillCreditCardEnabled" = $false
        "AutofillAddressEnabled" = $false
        "DefaultCookiesSetting" = 1  # 1 = Allow, 2 = Block (keep allow for general browsing)
        "PasswordManagerEnabled" = $true  # Keep password manager but block payment info
    }
    
    $policyFile = "$policiesPath\managed_policies.json"
    $managedPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $policyFile -Encoding UTF8 -Force
    Write-Host "$title [✓] Created managed policies: $policyFile" -ForegroundColor Green
    
    # Display blocked patterns
    Write-Host "$title Blocked URL patterns:" -ForegroundColor Cyan
    $managedPolicies.BlockedUrlPatterns | ForEach-Object {
        Write-Host "    - $_" -ForegroundColor Gray
    }
    
    # 2. Modify Default profile Preferences
    Write-Host "`n$title Modifying Comet preferences..." -ForegroundColor Cyan
    $defaultProfilePath = "$cometUserData\Default"
    $prefsPath = "$defaultProfilePath\Preferences"
    
    if (Test-Path $prefsPath) {
        # Backup original preferences
        $backupPath = "$prefsPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -Path $prefsPath -Destination $backupPath -Force
        Write-Host "$title [✓] Backed up preferences to: $backupPath" -ForegroundColor Green
        
        # Load and modify preferences
        $prefsContent = Get-Content $prefsPath -Raw -Encoding UTF8
        $prefs = $prefsContent | ConvertFrom-Json
        
        # Ensure profile object exists
        if (-not $prefs.profile) { 
            $prefs | Add-Member -NotePropertyName "profile" -NotePropertyValue @{} -Force
        }
        
        # Disable autofill for payment methods
        if (-not $prefs.autofill) {
            $prefs | Add-Member -NotePropertyName "autofill" -NotePropertyValue @{} -Force
        }
        $prefs.autofill | Add-Member -NotePropertyName "credit_card_enabled" -NotePropertyValue $false -Force
        $prefs.autofill | Add-Member -NotePropertyName "profile_enabled" -NotePropertyValue $false -Force
        
        # Block payment handlers in content settings
        if (-not $prefs.profile.content_settings) { 
            $prefs.profile | Add-Member -NotePropertyName "content_settings" -NotePropertyValue @{} -Force
        }
        if (-not $prefs.profile.content_settings.exceptions) {
            $prefs.profile.content_settings | Add-Member -NotePropertyName "exceptions" -NotePropertyValue @{} -Force
        }
        
        # Add payment handler blocks
        $prefs.profile.content_settings.exceptions | Add-Member -NotePropertyName "payment_handler" -NotePropertyValue @{
            "[*.]perplexity.ai,*" = @{ "setting" = 2 }  # 2 = block
            "comet://settings/*,*" = @{ "setting" = 2 }
        } -Force
        
        # Save modified preferences
        $prefs | ConvertTo-Json -Depth 10 -Compress:$false | Out-File -FilePath $prefsPath -Encoding UTF8 -Force
        Write-Host "$title [✓] Updated Comet preferences to block payment features" -ForegroundColor Green
    } else {
        Write-Host "$title Default profile preferences not found. Run Comet once to create the profile." -ForegroundColor Yellow
    }
    
    # 3. Create a Local State override (optional, for extra protection)
    $localStatePath = "$cometUserData\Local State"
    if (Test-Path $localStatePath) {
        $localState = Get-Content $localStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        
        # Disable payment-related features at browser level
        if (-not $localState.browser) {
            $localState | Add-Member -NotePropertyName "browser" -NotePropertyValue @{} -Force
        }
        $localState.browser | Add-Member -NotePropertyName "payments_integration_enabled" -NotePropertyValue $false -Force
        
        # Backup and save
        $backupLocalState = "$localStatePath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -Path $localStatePath -Destination $backupLocalState -Force
        
        $localState | ConvertTo-Json -Depth 10 -Compress:$false | Out-File -FilePath $localStatePath -Encoding UTF8 -Force
        Write-Host "$title [✓] Updated Local State to disable payment integration" -ForegroundColor Green
    }
    
    # Summary
    Write-Host "`n$title Summary:" -ForegroundColor Cyan
    Write-Host "  ✓ Managed policies created with URL blocking" -ForegroundColor Green
    Write-Host "  ✓ Payment handler blocked in content settings" -ForegroundColor Green
    Write-Host "  ✓ Autofill for credit cards disabled" -ForegroundColor Green
    Write-Host "  ✓ Payment integration disabled" -ForegroundColor Green
    Write-Host "`n$title Payment and billing features have been blocked in Comet." -ForegroundColor Green
    Write-Host "$title Restart Comet for changes to take effect." -ForegroundColor Yellow
    
} catch {
    Write-Host "$title ERROR: Failed to modify Comet configuration - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}