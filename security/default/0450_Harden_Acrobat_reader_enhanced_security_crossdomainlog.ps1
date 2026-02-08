<#
.SYNOPSIS
    Configure Adobe Acrobat/Reader DC cross-domain logging in the current user profile.

.DESCRIPTION
    This script manages the registry value:
      HKCU:\Software\Adobe\*\DC\AVPrivate\bCrossDomainLogging

    Default behavior enables logging (value = 1). The script:
    - Detects supported product roots (Acrobat Reader DC and Acrobat DC).
    - Creates missing child paths (DC and AVPrivate) when product super-root exists.
    - Creates or remediates bCrossDomainLogging to desired state.
    - Emits per-target status and a final summary.

    If no product super-root is present for a target, it is reported as warning and skipped.

.PARAMETER Mode
    Desired state for bCrossDomainLogging.
    - Enable  => sets value to 1
    - Disable => sets value to 0
    Default: Enable

.PARAMETER ConfigureAllDetected
    By default, only the first detected product target is configured to avoid duplicate actions
    when both Acrobat Reader DC and Acrobat DC are present.
    Use this switch to configure all detected targets.

.PARAMETER PauseOnError
    Pause for input when an unrecoverable error occurs (for interactive runs).

.PARAMETER PauseAtEnd
    Pause for input at the end of script execution (for interactive runs).

.PARAMETER PromptBeforeElevation
    When not running as Administrator, ask for user confirmation before showing UAC prompt.
    Default: True

.EXAMPLE
    .\0450_Harden_Acrobat_reader_enhanced_security_crossdomainlog.ps1
    Enables cross-domain logging on the first detected target.

.EXAMPLE
    .\0450_Harden_Acrobat_reader_enhanced_security_crossdomainlog.ps1 -Mode Disable
    Disables cross-domain logging on the first detected target.

.EXAMPLE
    .\0450_Harden_Acrobat_reader_enhanced_security_crossdomainlog.ps1 -ConfigureAllDetected
    Enables cross-domain logging on all detected Acrobat/Reader DC targets.

.NOTES
    Script: 0450_Harden_Acrobat_reader_enhanced_security_crossdomainlog.ps1
    Scope : Current user (HKCU)
#>

[CmdletBinding()]
param(
    [ValidateSet("Enable", "Disable")]
    [string]$Mode = "Enable",
    [switch]$ConfigureAllDetected,
    [bool]$PauseOnError = $true,
    [bool]$PauseAtEnd = $true,
    [bool]$PromptBeforeElevation = $true
)

$title = "[0450_Harden_Acrobat_reader_enhanced_security_crossdomainlog]"
$name = "bCrossDomainLogging"
$desiredValue = if ($Mode -eq "Enable") { 1 } else { 0 }
$desiredLabel = if ($Mode -eq "Enable") { "ENABLED" } else { "DISABLED" }

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

if (-not (Test-IsAdministrator)) {
    $elevate = $true
    if ($PromptBeforeElevation) {
        Write-Host "$title [INFO] Some registry targets may require Administrator privileges."
        try {
            $answer = Read-Host "Show UAC prompt to elevate now? (Y/N, default: Y)"
            if (($answer -ne $null) -and ($answer.Trim().Length -gt 0) -and ($answer.Trim().Substring(0,1).ToUpper() -ne "Y")) {
                $elevate = $false
            }
        } catch {
            # Non-interactive host: keep default behavior (elevate).
        }
    }

    if ($elevate) {
        Write-Host "$title [INFO] Prompting for UAC approval..."
        try {
            Start-ElevatedSelf -BoundParameters $PSBoundParameters
            Write-Host "$title [INFO] Elevated session started. This non-elevated session will now exit."
            if ($PauseAtEnd) {
                Wait-ForUserBeforeExit -Message "Press Enter to close this window..."
            }
            return
        } catch {
            Write-Warning "$title Elevation was declined or unavailable. Exiting without changes."
            if ($PauseAtEnd) {
                Wait-ForUserBeforeExit -Message "Press Enter to exit..."
            }
            return
        }
    } else {
        Write-Host "$title [INFO] Elevation declined by user. Exiting without changes."
        if ($PauseAtEnd) {
            Wait-ForUserBeforeExit -Message "Press Enter to exit..."
        }
        return
    }
}

$targets = @(
    @{
        Product = "Adobe Acrobat DC"
        SuperRootPath = "HKCU:\Software\Adobe\Adobe Acrobat"
        ParentPath = "HKCU:\Software\Adobe\Adobe Acrobat\DC"
        Path = "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVPrivate"
    },
    @{
        Product = "Acrobat Reader DC"
        SuperRootPath = "HKCU:\Software\Adobe\Acrobat Reader"
        ParentPath = "HKCU:\Software\Adobe\Acrobat Reader\DC"
        Path = "HKCU:\Software\Adobe\Acrobat Reader\DC\AVPrivate"
    },
    @{
        Product = "Acrobat DC"
        SuperRootPath = "HKCU:\Software\Adobe\Acrobat"
        ParentPath = "HKCU:\Software\Adobe\Acrobat\DC"
        Path = "HKCU:\Software\Adobe\Acrobat\DC\AVPrivate"
    }
)

$results = @()
$detectedTargets = @($targets | Where-Object { Test-Path -Path $_.SuperRootPath })
$missingTargets = @($targets | Where-Object { -not (Test-Path -Path $_.SuperRootPath) })

foreach ($target in $missingTargets) {
    $product = $target.Product
    $superRootPath = $target.SuperRootPath
    Write-Warning "$title [$product] Super-root missing. Product appears not installed for current user: $superRootPath"
    $results += [pscustomobject]@{
        Product = $product
        SuperRootPath = $superRootPath
        ParentPath = $target.ParentPath
        Path = $target.Path
        Status = "WARNING_SUPERROOT_MISSING"
        Action = "SKIPPED"
    }
}

if ($detectedTargets.Count -eq 0) {
    Write-Host ""
    Write-Host "$title Summary (Mode=$Mode, Desired=$desiredValue/$desiredLabel):"
    foreach ($result in $results) {
        Write-Host ("{0} | {1} | action={2} | superroot={3} | parent={4} | path={5}" -f $result.Product, $result.Status, $result.Action, $result.SuperRootPath, $result.ParentPath, $result.Path)
    }
    if ($PauseAtEnd) {
        Wait-ForUserBeforeExit -Message "Press Enter to exit..."
    }
    return
}

$targetsToConfigure = $detectedTargets
$configuredOne = $false

foreach ($target in $targetsToConfigure) {
    $product = $target.Product
    $superRootPath = $target.SuperRootPath
    $parentPath = $target.ParentPath
    $path = $target.Path

    if ((-not $ConfigureAllDetected) -and $configuredOne) {
        Write-Host "$title [$product] [SKIPPED] single-target mode already configured another detected product; use -ConfigureAllDetected to configure all products"
        $results += [pscustomobject]@{
            Product = $product
            SuperRootPath = $superRootPath
            ParentPath = $parentPath
            Path = $path
            Status = "SKIPPED_DUPLICATE_TARGET"
            Action = "NONE"
        }
        continue
    }

    try {
        if (-not (Test-Path -Path $parentPath)) {
            New-Item -Path $parentPath -Force -ErrorAction Stop | Out-Null
            Write-Host "$title [$product] [PRODUCT ROOT CREATED] $parentPath"
        }

        if (-not (Test-Path -Path $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
            Write-Host "$title [$product] [AVPRIVATE CREATED] $path"
        }

        $item = Get-ItemProperty -Path $path -ErrorAction Stop
        if ($item.PSObject.Properties.Name -contains $name) {
            $currentValue = $item.$name
        } else {
            $currentValue = $null
        }

        if ($null -eq $currentValue) {
            New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $desiredValue -Force -ErrorAction Stop | Out-Null
            Write-Host "$title [$product] [VALUE CREATED] $path\$name = $desiredValue ($desiredLabel)"
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                Path = $path
                Status = "CONFIGURED"
                Action = "CREATED_VALUE"
            }
            $configuredOne = $true
            continue
        }

        if ([int]$currentValue -eq $desiredValue) {
            Write-Host "$title [$product] [ON TARGET] $path\$name = $desiredValue ($desiredLabel)"
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                Path = $path
                Status = "ON_TARGET"
                Action = "NONE"
            }
            $configuredOne = $true
            continue
        }

        Set-ItemProperty -Path $path -Name $name -Type DWord -Value $desiredValue -Force -ErrorAction Stop
        Write-Host "$title [$product] [REMEDIATED] $path\$name current=$currentValue expected=$desiredValue ($desiredLabel)"
        $results += [pscustomobject]@{
            Product = $product
            SuperRootPath = $superRootPath
            ParentPath = $parentPath
            Path = $path
            Status = "CONFIGURED"
            Action = "SET_VALUE"
        }
        $configuredOne = $true
    } catch {
        Write-Warning "$title [$product] Access denied or write failure at $path : $($_.Exception.Message)"
        $results += [pscustomobject]@{
            Product = $product
            SuperRootPath = $superRootPath
            ParentPath = $parentPath
            Path = $path
            Status = "WARNING_WRITE_FAILED"
            Action = "SKIPPED"
        }
    }
}

Write-Host ""
Write-Host "$title Summary (Mode=$Mode, Desired=$desiredValue/$desiredLabel):"
foreach ($result in $results) {
    Write-Host ("{0} | {1} | action={2} | superroot={3} | parent={4} | path={5}" -f $result.Product, $result.Status, $result.Action, $result.SuperRootPath, $result.ParentPath, $result.Path)
}

Write-Host "Ensure activation in Enhanced Security section of cross domain log generation."

if ($PauseAtEnd) {
    Wait-ForUserBeforeExit -Message "Press Enter to exit..."
}
