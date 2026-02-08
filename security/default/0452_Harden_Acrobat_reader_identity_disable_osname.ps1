<#
.SYNOPSIS
    Harden Adobe Acrobat/Reader DC comment identity to avoid exposing OS login name.

.DESCRIPTION
    This script configures comment author preferences under HKCU so local comments do not
    default to the Windows login name.

    Primary intent:
    - Disable "Always use Log-In Name for Author name" behavior (best-effort via known flags).
    - Set default comment author to a user-controlled value (default: Anonymous).
    - Set generic Identity fields (default name: Anonymous Reviewer).

    Workflow:
    - Ensure Acrobat/Reader is closed before applying changes.
    - Use opt-in UAC elevation flow when needed.
    - Detect supported product roots and configure target(s).
    - Emit per-target status and final summary.

.PARAMETER Mode
    Desired state:
    - Enable  => privacy mode (do not use OS login name, default author anonymous)
    - Disable => revert to OS-name-like behavior where supported
    Default: Enable

.PARAMETER DefaultAuthor
    Default comment author written to tauthor.
    Default: Anonymous

.PARAMETER DefaultIdentityName
    Identity Name field value for privacy mode.
    Default: Anonymous Reviewer

.PARAMETER ConfigureAllDetected
    By default, only the first detected product target is configured.
    Use this switch to configure all detected targets.

.PARAMETER PauseOnError
    Pause for input on unrecoverable errors.

.PARAMETER PauseAtEnd
    Pause for input at script end.

.PARAMETER PromptBeforeElevation
    Ask user confirmation before showing UAC prompt.
    Default: True

.NOTES
    References:
    - Adobe Community: login name in comments / identity behavior
      https://community.adobe.com/questions-12/how-to-change-your-login-name-1520651
#>

[CmdletBinding()]
param(
    [ValidateSet("Enable", "Disable")]
    [string]$Mode = "Enable",
    [string]$DefaultAuthor = "Anonymous",
    [string]$DefaultIdentityName = "Anonymous Reviewer",
    [switch]$ConfigureAllDetected,
    [bool]$PauseOnError = $true,
    [bool]$PauseAtEnd = $true,
    [bool]$PromptBeforeElevation = $true,
    [string]$ResultFilePath = ""
)

$title = "[0452_Harden_Acrobat_reader_identity_disable_osname]"
$desiredLabel = if ($Mode -eq "Enable") { "PRIVACY_MODE" } else { "DEFAULT_MODE" }

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

    $process = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argumentList -PassThru -ErrorAction Stop
    $process.WaitForExit()
    return $process.ExitCode
}

function Wait-ForUserBeforeExit {
    param([string]$Message = "Press Enter to exit...")
    try {
        [void](Read-Host $Message)
    } catch {
        # Ignore if running non-interactive
    }
}

function Test-AcrobatProcessesRunning {
    $names = @("Acrobat", "AcroRd32")
    $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName })
    return $running
}

function Write-SynthesisResult {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($ResultFilePath)) {
        return
    }

    try {
        Set-Content -Path $ResultFilePath -Value $Message -Encoding UTF8 -Force
    } catch {
        # Ignore synthesis write failures.
    }
}

function Ensure-RegistryPath {
    param([string]$Path)
    if (Test-Path -Path $Path) {
        return $false
    }
    New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    return $true
}

function Set-RegistryValueIfNeeded {
    param(
        [string]$Path,
        [string]$Name,
        [ValidateSet("DWord", "String")]
        [string]$PropertyType,
        [object]$DesiredValue
    )

    $item = Get-ItemProperty -Path $Path -ErrorAction Stop
    if ($item.PSObject.Properties.Name -contains $Name) {
        $currentValue = $item.$Name
    } else {
        $currentValue = $null
    }

    if ($PropertyType -eq "DWord") {
        if (($null -ne $currentValue) -and ([int]$currentValue -eq [int]$DesiredValue)) {
            return $false
        }
    } else {
        if (($null -ne $currentValue) -and ([string]$currentValue -ceq [string]$DesiredValue)) {
            return $false
        }
    }

    New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $DesiredValue -Force -ErrorAction Stop | Out-Null
    return $true
}

$runningProcesses = Test-AcrobatProcessesRunning
if ($runningProcesses.Count -gt 0) {
    $processList = ($runningProcesses.ProcessName | Sort-Object -Unique) -join ", "
    Write-Warning "$title Acrobat/Reader is running ($processList). Close Acrobat/Reader, then re-run this script."
    if ($PauseAtEnd) {
        Wait-ForUserBeforeExit -Message "Press Enter to exit..."
    }
    Write-SynthesisResult -Message "Feat: configures comment author preferences to not use oslogin. Action: no change, Acrobat/Reader process is running."
    return
}

if (-not (Test-IsAdministrator)) {
    $elevate = $true
    if ($PromptBeforeElevation) {
        Write-Host "$title [INFO] Administrator privileges may be required for some Acrobat registry branches."
        try {
            $answer = Read-Host "Show UAC prompt to elevate now? (Y/N, default: Y)"
            if (($null -ne $answer) -and ($answer.Trim().Length -gt 0) -and ($answer.Trim().Substring(0,1).ToUpper() -ne "Y")) {
                $elevate = $false
            }
        } catch {
            # Non-interactive host: keep default behavior (elevate).
        }
    }

    if ($elevate) {
        Write-Host "$title [INFO] Prompting for UAC approval..."
        try {
            $elevatedParams = @{}
            foreach ($entry in $PSBoundParameters.GetEnumerator()) {
                $elevatedParams[$entry.Key] = $entry.Value
            }
            $elevatedParams["ResultFilePath"] = Join-Path -Path $env:TEMP -ChildPath ("0452_identity_result_{0}.txt" -f ([guid]::NewGuid().ToString("N")))

            $null = Start-ElevatedSelf -BoundParameters $elevatedParams
            if (Test-Path -Path $elevatedParams["ResultFilePath"]) {
                $synthesis = Get-Content -Path $elevatedParams["ResultFilePath"] -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($synthesis)) {
                    Write-Host $synthesis
                }
                Remove-Item -Path $elevatedParams["ResultFilePath"] -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "Feat: configures comment author preferences to not use oslogin. Action: completed in elevated session."
            }
            return
        } catch {
            Write-Warning "$title Elevation was declined or unavailable. Exiting without changes."
            Write-Host "Feat: configures comment author preferences to not use oslogin. Action: nothing done."
            if ($PauseAtEnd) {
                Wait-ForUserBeforeExit -Message "Press Enter to exit..."
            }
            return
        }
    } else {
        Write-Host "$title [INFO] Elevation declined by user. Exiting without changes."
        Write-Host "Feat: configures comment author preferences to not use oslogin. Action: nothing done."
        if ($PauseAtEnd) {
            Wait-ForUserBeforeExit -Message "Press Enter to exit..."
        }
        return
    }
}

$targets = @(
    @{
        Product = "Acrobat Reader DC"
        SuperRootPath = "HKCU:\Software\Adobe\Acrobat Reader"
        ParentPath = "HKCU:\Software\Adobe\Acrobat Reader\DC"
        AnnotsRootPath = "HKCU:\Software\Adobe\Acrobat Reader\DC\Annots\cAnnots"
        CommentPath = "HKCU:\Software\Adobe\Acrobat Reader\DC\Annots\cAnnots\cAnnot"
        IdentityPath = "HKCU:\Software\Adobe\Acrobat Reader\DC\Identity"
    },
    @{
        Product = "Adobe Acrobat DC"
        SuperRootPath = "HKCU:\Software\Adobe\Adobe Acrobat"
        ParentPath = "HKCU:\Software\Adobe\Adobe Acrobat\DC"
        AnnotsRootPath = "HKCU:\Software\Adobe\Adobe Acrobat\DC\Annots\cAnnots"
        CommentPath = "HKCU:\Software\Adobe\Adobe Acrobat\DC\Annots\cAnnots\cAnnot"
        IdentityPath = "HKCU:\Software\Adobe\Adobe Acrobat\DC\Identity"
    },
    @{
        Product = "Acrobat DC"
        SuperRootPath = "HKCU:\Software\Adobe\Acrobat"
        ParentPath = "HKCU:\Software\Adobe\Acrobat\DC"
        AnnotsRootPath = "HKCU:\Software\Adobe\Acrobat\DC\Annots\cAnnots"
        CommentPath = "HKCU:\Software\Adobe\Acrobat\DC\Annots\cAnnots\cAnnot"
        IdentityPath = "HKCU:\Software\Adobe\Acrobat\DC\Identity"
    }
)

# Known preference names used across releases for "always use login name" style behavior.
$loginNamePreferenceKeys = @(
    "bAlwaysUseLogInName",
    "bAlwaysUseLoginName",
    "bUseLogInName",
    "bUseLoginName"
)

$results = @()
$detectedTargets = @($targets | Where-Object { Test-Path -Path $_.SuperRootPath })
$missingTargets = @($targets | Where-Object { -not (Test-Path -Path $_.SuperRootPath) })

foreach ($target in $missingTargets) {
    Write-Warning "$title [$($target.Product)] Super-root missing: $($target.SuperRootPath)"
    $results += [pscustomobject]@{
        Product = $target.Product
        SuperRootPath = $target.SuperRootPath
        ParentPath = $target.ParentPath
        CommentPath = $target.CommentPath
        Status = "WARNING_SUPERROOT_MISSING"
        Action = "SKIPPED"
    }
}

if ($detectedTargets.Count -eq 0) {
    Write-Host ""
    Write-Host "$title Summary (Mode=$Mode, Desired=$desiredLabel):"
    foreach ($result in $results) {
        Write-Host ("{0} | {1} | action={2} | superroot={3} | parent={4} | commentPath={5}" -f $result.Product, $result.Status, $result.Action, $result.SuperRootPath, $result.ParentPath, $result.CommentPath)
    }
    Write-Host "Purpose: prevent local document comments from leaking OS login name by default."
    Write-SynthesisResult -Message "Feat: configures comment author preferences to not use oslogin. Action: nothing done (target not found)."
    if ($PauseAtEnd) {
        Wait-ForUserBeforeExit -Message "Press Enter to exit..."
    }
    return
}

$targetsToConfigure = @()
if ($ConfigureAllDetected) {
    $targetsToConfigure = $detectedTargets
} else {
    $targetsToConfigure = @($detectedTargets | Select-Object -First 1)
    if ($detectedTargets.Count -gt 1) {
        Write-Host "$title [INFO] Multiple Acrobat profile roots detected. Using primary target: $($targetsToConfigure[0].Product)"
    }
}

foreach ($target in $targetsToConfigure) {
    $product = $target.Product
    $superRootPath = $target.SuperRootPath
    $parentPath = $target.ParentPath
    $annotsRootPath = $target.AnnotsRootPath
    $commentPath = $target.CommentPath
    $identityPath = $target.IdentityPath

    try {
        $changes = 0
        if (Ensure-RegistryPath -Path $parentPath) {
            $changes++
            Write-Host "$title [$product] [PRODUCT ROOT CREATED] $parentPath"
        }

        if (Ensure-RegistryPath -Path $annotsRootPath) {
            $changes++
            Write-Host "$title [$product] [ANNOTS ROOT CREATED] $annotsRootPath"
        }

        if (Ensure-RegistryPath -Path $commentPath) {
            $changes++
            Write-Host "$title [$product] [COMMENT PROFILE CREATED] $commentPath"
        }

        if (Ensure-RegistryPath -Path $identityPath) {
            $changes++
            Write-Host "$title [$product] [IDENTITY PATH CREATED] $identityPath"
        }

        if ($Mode -eq "Enable") {
            foreach ($prefName in $loginNamePreferenceKeys) {
                if (Set-RegistryValueIfNeeded -Path $annotsRootPath -Name $prefName -PropertyType DWord -DesiredValue 0) {
                    $changes++
                }
            }

            if (Set-RegistryValueIfNeeded -Path $commentPath -Name "tauthor" -PropertyType String -DesiredValue $DefaultAuthor) {
                $changes++
            }
            if (Set-RegistryValueIfNeeded -Path $identityPath -Name "tName" -PropertyType String -DesiredValue $DefaultIdentityName) {
                $changes++
            }
            if (Set-RegistryValueIfNeeded -Path $identityPath -Name "tOrganization" -PropertyType String -DesiredValue "Anonymous") {
                $changes++
            }

            if ($changes -eq 0) {
                Write-Host "$title [$product] [ON TARGET] Privacy settings already configured. No action required."
                $results += [pscustomobject]@{
                    Product = $product
                    SuperRootPath = $superRootPath
                    ParentPath = $parentPath
                    CommentPath = $commentPath
                    Status = "ON_TARGET"
                    Action = "NONE"
                }
            } else {
                Write-Host "$title [$product] [CONFIGURED] Disabled login-name-as-author and set comment defaults: Author='$DefaultAuthor', IdentityName='$DefaultIdentityName'"
                $results += [pscustomobject]@{
                    Product = $product
                    SuperRootPath = $superRootPath
                    ParentPath = $parentPath
                    CommentPath = $commentPath
                    Status = "CONFIGURED"
                    Action = "UPDATED"
                }
            }
            continue
        }

        foreach ($prefName in $loginNamePreferenceKeys) {
            if (Set-RegistryValueIfNeeded -Path $annotsRootPath -Name $prefName -PropertyType DWord -DesiredValue 1) {
                $changes++
            }
        }
        if (Set-RegistryValueIfNeeded -Path $commentPath -Name "tauthor" -PropertyType String -DesiredValue $env:USERNAME) {
            $changes++
        }
        if (Set-RegistryValueIfNeeded -Path $identityPath -Name "tName" -PropertyType String -DesiredValue $env:USERNAME) {
            $changes++
        }

        if ($changes -eq 0) {
            Write-Host "$title [$product] [ON TARGET] Default mode already configured. No action required."
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                CommentPath = $commentPath
                Status = "ON_TARGET"
                Action = "NONE"
            }
        } else {
            Write-Host "$title [$product] [CONFIGURED] Enabled login-name-as-author behavior and reverted Author/Identity to OS username"
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                CommentPath = $commentPath
                Status = "CONFIGURED"
                Action = "UPDATED"
            }
        }
    } catch {
        Write-Warning "$title [$product] Access denied or write failure: $($_.Exception.Message)"
        $results += [pscustomobject]@{
            Product = $product
            SuperRootPath = $superRootPath
            ParentPath = $parentPath
            CommentPath = $commentPath
            Status = "WARNING_WRITE_FAILED"
            Action = "SKIPPED"
        }
    }
}

Write-Host ""
Write-Host "$title Summary (Mode=$Mode, Desired=$desiredLabel):"
foreach ($result in $results) {
    Write-Host ("{0} | {1} | action={2} | superroot={3} | parent={4} | commentPath={5}" -f $result.Product, $result.Status, $result.Action, $result.SuperRootPath, $result.ParentPath, $result.CommentPath)
}

Write-Host "Purpose: avoid being forced to leak OS login name in comments; default author is user-controlled (Anonymous by default)."
$changedCount = @($results | Where-Object { $_.Action -eq "UPDATED" }).Count
if ($changedCount -gt 0) {
    $synthesis = "Feat: configures comment author preferences to not use oslogin. Action: updated."
} else {
    $synthesis = "Feat: configures comment author preferences to not use oslogin. Action: already on target, nothing done."
}
Write-Host $synthesis
Write-SynthesisResult -Message $synthesis

if ($PauseAtEnd) {
    Wait-ForUserBeforeExit -Message "Press Enter to exit..."
}
