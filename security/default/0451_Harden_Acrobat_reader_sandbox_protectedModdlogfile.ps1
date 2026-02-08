<#
.SYNOPSIS
    Configure Adobe Acrobat/Reader DC Sandbox "Create Protected Mode log file".

.DESCRIPTION
    This script manages the registry value:
      HKCU:\Software\Adobe\*\DC\Privileged\tBrokerLogfilePath

    Default behavior enables Protected Mode logging by setting a log file path.
    Disable mode removes the value.

    Workflow:
    - Ensures Acrobat is not running before applying changes.
    - Uses opt-in UAC elevation flow when needed.
    - Detects supported product roots and configures target(s).
    - Emits per-target status and final summary.

.PARAMETER Mode
    Desired state:
    - Enable  => set tBrokerLogfilePath
    - Disable => remove tBrokerLogfilePath
    Default: Enable

.PARAMETER ConfigureAllDetected
    By default, only the first detected product target is configured.
    Use this switch to configure all detected targets.

.PARAMETER LogFilePath
    Log file path used when Mode is Enable.
    Default: %LOCALAPPDATA%\Adobe\Acrobat\DC\ProtectedMode\broker.log

.PARAMETER PauseOnError
    Pause for input when an unrecoverable error occurs.

.PARAMETER PauseAtEnd
    Pause for input at the end of script execution.

.PARAMETER PromptBeforeElevation
    Ask user confirmation before showing UAC prompt.
    Default: True
#>

[CmdletBinding()]
param(
    [ValidateSet("Enable", "Disable")]
    [string]$Mode = "Enable",
    [switch]$ConfigureAllDetected,
    [string]$LogFilePath = "$env:LOCALAPPDATA\Adobe\Acrobat\DC\ProtectedMode\broker.log",
    [bool]$PauseOnError = $true,
    [bool]$PauseAtEnd = $true,
    [bool]$PromptBeforeElevation = $true
)

$title = "[0451_Harden_Acrobat_reader_sandbox_protectedModdlogfile]"
$name = "tBrokerLogfilePath"
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

$runningProcesses = Test-AcrobatProcessesRunning
if ($runningProcesses.Count -gt 0) {
    $processList = ($runningProcesses.ProcessName | Sort-Object -Unique) -join ", "
    Write-Warning "$title Acrobat/Reader is running ($processList). Close Acrobat/Reader, then re-run this script."
    if ($PauseAtEnd) {
        Wait-ForUserBeforeExit -Message "Press Enter to exit..."
    }
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
        Path = "HKCU:\Software\Adobe\Adobe Acrobat\DC\Privileged"
    },
    @{
        Product = "Acrobat Reader DC"
        SuperRootPath = "HKCU:\Software\Adobe\Acrobat Reader"
        ParentPath = "HKCU:\Software\Adobe\Acrobat Reader\DC"
        Path = "HKCU:\Software\Adobe\Acrobat Reader\DC\Privileged"
    },
    @{
        Product = "Acrobat DC"
        SuperRootPath = "HKCU:\Software\Adobe\Acrobat"
        ParentPath = "HKCU:\Software\Adobe\Acrobat\DC"
        Path = "HKCU:\Software\Adobe\Acrobat\DC\Privileged"
    }
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
        Path = $target.Path
        Status = "WARNING_SUPERROOT_MISSING"
        Action = "SKIPPED"
    }
}

if ($detectedTargets.Count -eq 0) {
    Write-Host ""
    Write-Host "$title Summary (Mode=$Mode, Setting=$name):"
    foreach ($result in $results) {
        Write-Host ("{0} | {1} | action={2} | superroot={3} | parent={4} | path={5}" -f $result.Product, $result.Status, $result.Action, $result.SuperRootPath, $result.ParentPath, $result.Path)
    }
    Write-Host "Purpose: Configure Sandbox Protections -> Create Protected Mode log file."
    if ($PauseAtEnd) {
        Wait-ForUserBeforeExit -Message "Press Enter to exit..."
    }
    return
}

$configuredOne = $false
foreach ($target in $detectedTargets) {
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
            Write-Host "$title [$product] [PRIVILEGED CREATED] $path"
        }

        $item = Get-ItemProperty -Path $path -ErrorAction Stop
        if ($item.PSObject.Properties.Name -contains $name) {
            $currentValue = [string]$item.$name
        } else {
            $currentValue = $null
        }

        if ($Mode -eq "Enable") {
            if ([string]::IsNullOrWhiteSpace($currentValue)) {
                New-ItemProperty -Path $path -Name $name -PropertyType String -Value $LogFilePath -Force -ErrorAction Stop | Out-Null
                Write-Host "$title [$product] [VALUE CREATED] $path\$name = $LogFilePath ($desiredLabel)"
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

            if ($currentValue -ceq $LogFilePath) {
                Write-Host "$title [$product] [ON TARGET] $path\$name = $LogFilePath ($desiredLabel)"
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

            Set-ItemProperty -Path $path -Name $name -Type String -Value $LogFilePath -Force -ErrorAction Stop
            Write-Host "$title [$product] [REMEDIATED] $path\$name current=$currentValue expected=$LogFilePath ($desiredLabel)"
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                Path = $path
                Status = "CONFIGURED"
                Action = "SET_VALUE"
            }
            $configuredOne = $true
            continue
        }

        if ($item.PSObject.Properties.Name -contains $name) {
            Remove-ItemProperty -Path $path -Name $name -ErrorAction Stop
            Write-Host "$title [$product] [REMEDIATED] removed $path\$name ($desiredLabel)"
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                Path = $path
                Status = "CONFIGURED"
                Action = "REMOVED_VALUE"
            }
        } else {
            Write-Host "$title [$product] [ON TARGET] $path\$name already absent ($desiredLabel)"
            $results += [pscustomobject]@{
                Product = $product
                SuperRootPath = $superRootPath
                ParentPath = $parentPath
                Path = $path
                Status = "ON_TARGET"
                Action = "NONE"
            }
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
Write-Host "$title Summary (Mode=$Mode, Setting=$name, Desired=$desiredLabel):"
foreach ($result in $results) {
    Write-Host ("{0} | {1} | action={2} | superroot={3} | parent={4} | path={5}" -f $result.Product, $result.Status, $result.Action, $result.SuperRootPath, $result.ParentPath, $result.Path)
}

Write-Host "Purpose: Configure Sandbox Protections -> Create Protected Mode log file for troubleshooting and security analysis."

if ($PauseAtEnd) {
    Wait-ForUserBeforeExit -Message "Press Enter to exit..."
}
