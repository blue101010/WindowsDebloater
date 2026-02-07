<#
.SYNOPSIS
    Harden Adobe Acrobat DC policy registry settings using STIG/NSA-aligned values.

.DESCRIPTION
    This script validates and configures Acrobat hardening registry values.
    For each setting:
    1) Verify registry path exists (create it if missing).
    2) Verify registry value exists.
    3) Verify value is On Target (desired intent).
    4) If Off Target, print current value and set it.

    Implementation constraint:
    - Environment is policy-driven at:
      HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown
    - Do not use legacy "...\\2015\\..." locations.

.NOTES
    References:
    - Tenable DISA STIG Audit (Adobe Acrobat Reader DC Classic Track v2r1, Revision 1.8):
      https://www.tenable.com/audits/DISA_STIG_Adobe_Acrobat_Reader_DC_Classic_Track_v2r1
    - NSA Cybersecurity Technical Report - Configuring Adobe Acrobat Reader:
      https://media.defense.gov/2022/Jan/20/2002924940/-1/-1/1/CTR_CONFIGURING_ADOBE_ACROBAT_READER_20220120.PDF
#>

[CmdletBinding()]
param(
    [bool]$IncludeNsaControls = $true,
    [bool]$IncludeNonPolicyControls = $true,
    [bool]$PauseOnError = $true,
    [bool]$PauseAtEnd = $true
)

$title = "[0449_Harden_Acrobat_reader_STIG]"
$policyBase = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown"
$readerPolicyBase = "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ElevatedSelf {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    if (-not $PSCommandPath) {
        throw "Cannot self-elevate because PSCommandPath is not available."
    }

    $argumentList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )

    foreach ($entry in $BoundParameters.GetEnumerator()) {
        $paramName = $entry.Key
        $paramValue = $entry.Value
        if ($paramValue -is [bool]) {
            $argumentList += "-$paramName`:$paramValue"
        } elseif ($null -ne $paramValue) {
            $escapedValue = $paramValue.ToString().Replace('"', '\"')
            $argumentList += "-$paramName"
            $argumentList += "`"$escapedValue`""
        }
    }

    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argumentList -ErrorAction Stop | Out-Null
}

function Wait-ForUserBeforeExit {
    param(
        [string]$Message = "Press Enter to exit..."
    )

    try {
        [void](Read-Host $Message)
    } catch {
        # Ignore if running non-interactive
    }
}

function Set-RegistryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -Path $Path) {
        Write-Host "$title Path exists: $Path"
        return
    }

    try {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        Write-Host "$title Path created: $Path"
    } catch {
        Write-Error "$title Failed to create path: $Path. $($_.Exception.Message)"
        throw
    }
}

function Set-RegistryValueCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string[]]$Names,
        [Parameter(Mandatory = $true)]
        [object]$DesiredValue,
        [Parameter(Mandatory = $true)]
        [string]$ControlId,
        [Parameter(Mandatory = $true)]
        [string]$Reference,
        [ValidateSet("DWord", "String")]
        [string]$PropertyType = "DWord"
    )

    Set-RegistryPath -Path $Path

    $targetName = $Names[0]
    $currentValue = $null
    foreach ($candidate in $Names) {
        $candidateValue = Get-ItemPropertyValue -Path $Path -Name $candidate -ErrorAction SilentlyContinue
        if ($null -ne $candidateValue) {
            $targetName = $candidate
            $currentValue = $candidateValue
            break
        }
    }

    if ($null -eq $currentValue) {
        try {
            New-ItemProperty -Path $Path -Name $targetName -PropertyType $PropertyType -Value $DesiredValue -Force -ErrorAction Stop | Out-Null
            Write-Host "$title [$ControlId] [CREATED] $Path\$targetName = $DesiredValue (Reference: $Reference)"
        } catch {
            Write-Error "$title [$ControlId] Failed to create value: $Path\$targetName. $($_.Exception.Message)"
            throw
        }
        return
    }

    if ($PropertyType -eq "DWord") {
        $currentValue = [int]$currentValue
        $DesiredValue = [int]$DesiredValue
    } else {
        $currentValue = [string]$currentValue
        $DesiredValue = [string]$DesiredValue
    }

    if ($currentValue -ceq $DesiredValue) {
        Write-Host "$title [$ControlId] [ON TARGET] $Path\$targetName = $currentValue (Reference: $Reference)"
        return
    }

    Write-Host "$title [$ControlId] [OFF TARGET] $Path\$targetName current=$currentValue expected=$DesiredValue (Reference: $Reference)"
    try {
        Set-ItemProperty -Path $Path -Name $targetName -Type $PropertyType -Value $DesiredValue -Force -ErrorAction Stop
        Write-Host "$title [$ControlId] [SET] $Path\$targetName = $DesiredValue"
    } catch {
        Write-Error "$title [$ControlId] Failed to set value: $Path\$targetName. $($_.Exception.Message)"
        throw
    }
}

$settings = @(
    # Original user baseline (must stay present as-is for Acrobat Reader DC path).
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bAcroSuppressUpsell"); Value = 1; Type = "DWord"; Reference = "Original baseline: suppress upsell" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bDisablePDFHandlerSwitching"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable PDF handler switching" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bDisableTrustedFolders"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable trusted folders" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bDisableTrustedSites"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable trusted sites" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bEnableFlash"); Value = 0; Type = "DWord"; Reference = "Original baseline: disable Flash" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bEnhancedSecurityInBrowser"); Value = 1; Type = "DWord"; Reference = "Original baseline: enhanced security in browser" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bEnhancedSecurityStandalone"); Value = 1; Type = "DWord"; Reference = "Original baseline: enhanced security standalone" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("bProtectedMode"); Value = 1; Type = "DWord"; Reference = "Original baseline: protected mode" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("iFileAttachmentPerms"); Value = 1; Type = "DWord"; Reference = "Original baseline: file attachment permissions" },
    @{ Control = "ORIG-BASELINE"; Path = $readerPolicyBase; Name = @("iProtectedView"); Value = 2; Type = "DWord"; Reference = "Original baseline: protected view" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cCloud"; Name = @("bAdobeSendPluginToggle"); Value = 1; Type = "DWord"; Reference = "Original baseline: cCloud setting" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cDefaultLaunchURLPerms"; Name = @("iURLPerms"); Value = 1; Type = "DWord"; Reference = "Original baseline: URL perms" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cDefaultLaunchURLPerms"; Name = @("iUnknownURLPerms"); Value = 3; Type = "DWord"; Reference = "Original baseline: unknown URL perms" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cServices"; Name = @("bToggleAdobeDocumentServices"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable doc services" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cServices"; Name = @("bToggleAdobeSign"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable Adobe Sign" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cServices"; Name = @("bTogglePrefsSync"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable pref sync" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cServices"; Name = @("bToggleWebConnectors"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable web connectors" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cServices"; Name = @("bUpdater"); Value = 0; Type = "DWord"; Reference = "Original baseline: disable updater" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cSharePoint"; Name = @("bDisableSharePointFeatures"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable SharePoint features" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cWebmailProfiles"; Name = @("bDisableWebmail"); Value = 1; Type = "DWord"; Reference = "Original baseline: disable webmail" },
    @{ Control = "ORIG-BASELINE"; Path = "$readerPolicyBase\cWelcomeScreen"; Name = @("bShowWelcomeScreen"); Value = 0; Type = "DWord"; Reference = "Original baseline: disable welcome screen" },

    # DISA Classic Track v2r1 control mapping to deployed DC policy path (non-2015).
    @{ Control = "ARDC-CL-000005"; Path = $policyBase; Name = @("bEnhancedSecurityStandalone"); Value = 1; Type = "DWord"; Reference = "Enable Enhanced Security (Standalone)" },
    @{ Control = "ARDC-CL-000010"; Path = $policyBase; Name = @("bEnhancedSecurityInBrowser"); Value = 1; Type = "DWord"; Reference = "Enable Enhanced Security (Browser)" },
    @{ Control = "ARDC-CL-000015"; Path = $policyBase; Name = @("bProtectedMode"); Value = 1; Type = "DWord"; Reference = "Enable Protected Mode" },
    @{ Control = "ARDC-CL-000020"; Path = $policyBase; Name = @("iProtectedView"); Value = 2; Type = "DWord"; Reference = "Enable Protected View" },
    @{ Control = "ARDC-CL-000025"; Path = "$policyBase\cDefaultLaunchURLPerms"; Name = @("iURLPerms"); Value = 1; Type = "DWord"; Reference = "Block websites by default" },
    @{ Control = "ARDC-CL-000030"; Path = "$policyBase\cDefaultLaunchURLPerms"; Name = @("iUnknownURLPerms"); Value = 3; Type = "DWord"; Reference = "Block unknown websites" },
    @{ Control = "ARDC-CL-000035"; Path = $policyBase; Name = @("iFileAttachmentPerms"); Value = 1; Type = "DWord"; Reference = "Prevent opening non-PDF/FDF attachments" },
    @{ Control = "ARDC-CL-000045"; Path = $policyBase; Name = @("bEnableFlash"); Value = 0; Type = "DWord"; Reference = "Block Flash content" },
    @{ Control = "ARDC-CL-000050"; Path = $policyBase; Name = @("bDisablePDFHandlerSwitching"); Value = 1; Type = "DWord"; Reference = "Disable default handler switching" },
    @{ Control = "ARDC-CL-000055"; Path = "$policyBase\cCloud"; Name = @("bAdobeSendPluginToggle"); Value = 1; Type = "DWord"; Reference = "Disable Send and Track plugin" },
    @{ Control = "ARDC-CL-000060"; Path = "$policyBase\cServices"; Name = @("bToggleAdobeDocumentServices"); Value = 1; Type = "DWord"; Reference = "Disable document cloud services" },
    @{ Control = "ARDC-CL-000065"; Path = "$policyBase\cServices"; Name = @("bTogglePrefsSync", "bTogglePrefSync"); Value = 1; Type = "DWord"; Reference = "Disable cloud synchronization (supports both value spellings)" },
    @{ Control = "ARDC-CL-000075"; Path = "$policyBase\cServices"; Name = @("bToggleWebConnectors"); Value = 1; Type = "DWord"; Reference = "Disable third-party web connectors" },
    @{ Control = "ARDC-CL-000080"; Path = $policyBase; Name = @("bAcroSuppressUpsell"); Value = 1; Type = "DWord"; Reference = "Disable Acrobat upsell" },
    @{ Control = "ARDC-CL-000085"; Path = "$policyBase\cServices"; Name = @("bToggleAdobeSign"); Value = 1; Type = "DWord"; Reference = "Disable Adobe Sign" },
    @{ Control = "ARDC-CL-000090"; Path = "$policyBase\cWebmailProfiles"; Name = @("bDisableWebmail"); Value = 1; Type = "DWord"; Reference = "Disable webmail access" },
    @{ Control = "ARDC-CL-000100"; Path = "$policyBase\cSharePoint"; Name = @("bDisableSharePointFeatures"); Value = 1; Type = "DWord"; Reference = "Disable SharePoint access" },
    @{ Control = "ARDC-CL-000115"; Path = "$policyBase\cWelcomeScreen"; Name = @("bShowWelcomeScreen"); Value = 0; Type = "DWord"; Reference = "Disable welcome screen" },
    @{ Control = "ARDC-CL-000120"; Path = "$policyBase\cServices"; Name = @("bUpdater"); Value = 0; Type = "DWord"; Reference = "Disable service upgrades" },
    @{ Control = "ARDC-CL-000315"; Path = $policyBase; Name = @("bDisableTrustedFolders"); Value = 1; Type = "DWord"; Reference = "Disable trusted folders" },
    @{ Control = "ARDC-CL-000320"; Path = $policyBase; Name = @("bDisableTrustedSites"); Value = 1; Type = "DWord"; Reference = "Disable trusted sites" }
)

if ($IncludeNsaControls) {
    # NSA table additions coherent with deployed policy path model.
    $settings += @(
        @{ Control = "NSA-ATTACH-001"; Path = $policyBase; Name = @("iUnlistedAttachmentTypePerm"); Value = 3; Type = "DWord"; Reference = "Unlisted attachment types: always block" }
    )
}

if ($IncludeNonPolicyControls) {
    # These are outside FeatureLockDown but still valid hardening controls in many deployments.
    $settings += @(
        @{ Control = "ARDC-CL-000070"; Path = "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer"; Name = @("DisableMaintenance"); Value = 1; Type = "DWord"; Reference = "Disable repair/maintenance (Acrobat Reader 64-bit)" },
        @{ Control = "ARDC-CL-000070"; Path = "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer"; Name = @("DisableMaintenance"); Value = 1; Type = "DWord"; Reference = "Disable repair/maintenance (Acrobat Reader 32-bit)" },
        @{ Control = "ARDC-CL-000070"; Path = "HKLM:\Software\Adobe\Adobe Acrobat\DC\Installer"; Name = @("DisableMaintenance"); Value = 1; Type = "DWord"; Reference = "Disable repair/maintenance (Adobe Acrobat 64-bit)" },
        @{ Control = "ARDC-CL-000070"; Path = "HKLM:\Software\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer"; Name = @("DisableMaintenance"); Value = 1; Type = "DWord"; Reference = "Disable repair/maintenance (Adobe Acrobat 32-bit)" }
    )
}

$script:RunFailed = $false

try {
    Write-Host "$title Starting Adobe Acrobat DC hardening checks..."

    if (-not (Test-IsAdministrator)) {
        Write-Warning "$title This script requires Administrator rights to modify HKLM registry keys."
        $elevateChoice = Read-Host "$title Elevation is required. Launch UAC prompt now? (Y/N)"
        if ($elevateChoice -notmatch '^(?i)y(es)?$') {
            Write-Warning "$title Elevation declined by user. No hardening changes were applied."
            $script:RunFailed = $true
            if ($PauseOnError) { Wait-ForUserBeforeExit -Message "$title Press Enter to exit..." }
            return
        }

        try {
            Start-ElevatedSelf -BoundParameters $PSBoundParameters
            Write-Host "$title UAC elevation prompt launched. The elevated process will continue."
            return
        } catch {
            Write-Error "$title Elevation failed or was canceled. No hardening changes were applied."
            if ($PauseOnError) { Wait-ForUserBeforeExit -Message "$title Press Enter to exit..." }
            $script:RunFailed = $true
            return
        }
    }

    # Explicitly create original baseline Reader FeatureLockDown subkeys from prior script behavior.
    $originalBaselineSubkeys = @(
        "$readerPolicyBase\cCloud",
        "$readerPolicyBase\cDefaultLaunchURLPerms",
        "$readerPolicyBase\cServices",
        "$readerPolicyBase\cSharePoint",
        "$readerPolicyBase\cWebmailProfiles",
        "$readerPolicyBase\cWelcomeScreen"
    )
    foreach ($subkey in $originalBaselineSubkeys) {
        Set-RegistryPath -Path $subkey
    }

    foreach ($setting in $settings) {
        Set-RegistryValueCompliance -Path $setting.Path -Names $setting.Name -DesiredValue $setting.Value -ControlId $setting.Control -Reference $setting.Reference -PropertyType $setting.Type
    }

    Write-Host "$title [MANUAL] The following DISA controls are outside current policy-path constraint and were not auto-enforced:"
    if (-not $IncludeNonPolicyControls) {
        Write-Host "$title [MANUAL] ARDC-CL-000070 DisableMaintenance (Installer path)"
    }
    Write-Host "$title [MANUAL] ARDC-CL-000330 and ARDC-CL-000335 certificate list upload settings (Security path)"
    Write-Host "$title [MANUAL] ARDC-CL-000345 FIPS mode (AVGeneral path)"
    Write-Host "$title [MANUAL] ARDC-CL-000340 unsupported version removal (software lifecycle/process control)"

    Write-Host "$title [MANUAL] NSA optional controls not auto-enforced due ambiguous or org-specific values:"
    Write-Host "$title [MANUAL] tBuiltinPermList (REG_SZ default list), tHostPerms (approved host allowlist)"
    Write-Host "$title [MANUAL] bEnableAlwaysOutlookAttachmentProtectedView and HKCU TrustManager policies (if desired, add per-user policy scope)."

    Write-Host "$title Completed."
} catch {
    Write-Error "$title Fatal error: $($_.Exception.Message)"
    $script:RunFailed = $true
    if ($PauseOnError) { Wait-ForUserBeforeExit -Message "$title Press Enter to exit..." }
} finally {
    if ($PauseAtEnd -and -not $script:RunFailed) {
        Wait-ForUserBeforeExit -Message "$title Completed. Press Enter to close this window..."
    }
}
