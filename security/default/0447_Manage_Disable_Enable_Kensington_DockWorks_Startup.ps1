<#
.SYNOPSIS
    Manage Kensington DockWorks startup entries under Run registry keys.

.DESCRIPTION
    This script can check, disable (remove), or enable (restore) DockWorks
    startup entries from the standard Run locations. When disabling, matching
    entries are moved to a corresponding RunBackup key so they can be restored
    later with the 'enable' action.

.PARAMETER Action
    One of: 'disable' (default), 'enable', or 'check'.
    - 'disable' will move DockWorks Run entries into a RunBackup key.
    - 'enable' will restore entries from RunBackup back into Run.
    - 'check' will only report current status.

.EXAMPLE
    .\0447_Manage_Disable_Enable_Kensington_DockWorks_Startup.ps1
    (Defaults to disabling DockWorks startup entries when present.)

.EXAMPLE
    .\0447_Manage_Disable_Enable_Kensington_DockWorks_Startup.ps1 -Action check -Verbose

.NOTES
    Modifying HKLM keys requires elevation. The script will attempt actions
    and report permission errors if encountered.
#>

param(
    [Parameter(Position=0)]
    [ValidateSet('disable','enable','check')]
    [string]$Action = 'disable'
)

function Write-Log {
    param([string]$Message)
    Write-Output $Message
}

function Restore-RunValueFromBackup {
    param(
        [string]$RunPath
    )

    $restoredAny = $false
    $backupKey = ($RunPath -replace '\\Run$', '\\RunBackup')
    if (-not (Test-Path $backupKey)) {
        Write-Verbose "No backup key found at $backupKey"
        return $false
    }

    try {
        $props = Get-ItemProperty -Path $backupKey -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Cannot read backup key $backupKey : $_"
        return $false
    }

    $matches = $props.PSObject.Properties |
        Where-Object { $_.Name -notlike 'PS*' } |
        Where-Object { $_.Name -match 'DockWorks' -or ($_.Value -is [string] -and $_.Value -match 'DockWorks') }

    foreach ($m in $matches) {
        try {
            New-ItemProperty -Path $RunPath -Name $m.Name -Value $m.Value -PropertyType String -Force -ErrorAction Stop | Out-Null
            Remove-ItemProperty -Path $backupKey -Name $m.Name -Force -ErrorAction Stop
            Write-Log "Restored $($m.Name) to $RunPath"
            $restoredAny = $true
        } catch {
            Write-Log "ERROR: Failed to restore $($m.Name) from $backupKey : $_"
        }
    }

    return $restoredAny
}

function Backup-And-Remove-RunValue {
    param(
        [string]$RunPath
    )

    $changed = $false
    $backupKey = ($RunPath -replace '\\Run$', '\\RunBackup')
    if (-not (Test-Path $RunPath)) { return $false }

    try {
        $props = Get-ItemProperty -Path $RunPath -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Cannot read Run key $RunPath : $_"
        return $false
    }

    $matches = $props.PSObject.Properties |
        Where-Object { $_.Name -notlike 'PS*' } |
        Where-Object { $_.Name -match 'DockWorks' -or ($_.Value -is [string] -and $_.Value -match 'DockWorks') }

    if (-not $matches) {
        Write-Verbose "No DockWorks entries under $RunPath"
        return $false
    }

    try {
        if (-not (Test-Path $backupKey)) { New-Item -Path $backupKey -Force -ErrorAction Stop | Out-Null }
    } catch {
        Write-Log "ERROR: Cannot create backup key $backupKey : $_"
        return $false
    }

    foreach ($m in $matches) {
        try {
            New-ItemProperty -Path $backupKey -Name $m.Name -Value $m.Value -PropertyType String -Force -ErrorAction Stop | Out-Null
            Remove-ItemProperty -Path $RunPath -Name $m.Name -Force -ErrorAction Stop
            Write-Log "Backed up and removed $($m.Name) from $RunPath"
            $changed = $true
        } catch {
            Write-Log "ERROR: Failed to move $($m.Name) to backup: $_"
        }
    }

    return $changed
}

$runPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

Write-Log "Action: $Action"
Write-Log "Scanning Run keys for DockWorks entries..."

$status = @{}
foreach ($rp in $runPaths) {
    try {
        $props = Get-ItemProperty -Path $rp -ErrorAction Stop
        $matches = $props.PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            Where-Object { $_.Name -match 'DockWorks' -or ($_.Value -is [string] -and $_.Value -match 'DockWorks') } |
            ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }
    } catch {
        # If key does not exist, treat as no matches
        $matches = @()
    }

    if ($matches.Count -gt 0) {
        Write-Log "Found $($matches.Count) DockWorks entries under $rp"
        Write-Verbose ($matches | ForEach-Object { " - $($_.Name) = $($_.Value)" } )
        $status[$rp] = $matches
    } else {
        Write-Log "No DockWorks entries under $rp"
        $status[$rp] = @()
    }
}

# Service handling for KTGLDRService64
$serviceName = 'KTGLDRService64'
$serviceBackupReg = 'HKLM:\SOFTWARE\Windows10Debloater\Kensington\KTGLDRService64'

function Get-ServiceInfo {
    param([string]$Name)
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        return @{ StartMode = $svc.StartMode; State = $svc.State }
    } catch {
        return $null
    }
}

function Get-ServiceFullInfo {
    param([string]$Name)
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        return @{ Name = $svc.Name; DisplayName = $svc.DisplayName; State = $svc.State; StartMode = $svc.StartMode; PathName = $svc.PathName }
    } catch {
        return $null
    }
}

function Ensure-RegistryString {
    param([string]$Path,[string]$Name,[string]$Value)
    if (-not (Test-Path -Path $Path)) {
        try { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null } catch { Write-Log "ERROR: Cannot create $Path : $_"; return $false }
    }
    try {
        New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Log "ERROR: Cannot set $Path\$Name : $_"
        return $false
    }
}

function Backup-ServiceState {
    param([string]$Name)
    $info = Get-ServiceInfo -Name $Name
    if ($null -eq $info) { return $false }
    $ok = Ensure-RegistryString -Path $serviceBackupReg -Name 'OriginalStartMode' -Value $info.StartMode
    if (-not $ok) { return $false }
    $ok = Ensure-RegistryString -Path $serviceBackupReg -Name 'OriginalState' -Value $info.State
    return $ok
}

function Restore-ServiceState {
    param([string]$Name)
    if (-not (Test-Path $serviceBackupReg)) { return $false }
    try {
        $orig = Get-ItemProperty -Path $serviceBackupReg -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Cannot read service backup registry: $_"
        return $false
    }
    $startMode = $orig.OriginalStartMode
    $state = $orig.OriginalState
    try {
        if ($startMode -and $startMode -ne '') {
            try { Set-Service -Name $Name -StartupType $startMode -ErrorAction Stop } catch { sc.exe config $Name start= $((if ($startMode -eq 'Auto') {'auto'} elseif ($startMode -eq 'Manual') {'demand'} else {'demand'})) | Out-Null }
        }
        if ($state -eq 'Running') { Start-Service -Name $Name -ErrorAction SilentlyContinue }
        Remove-Item -Path $serviceBackupReg -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Log "ERROR: Failed to restore service $Name : $_"
        return $false
    }
}

function Set-ServiceToManualAndStop {
    param([string]$Name)
    $info = Get-ServiceInfo -Name $Name
    if ($null -eq $info) { return $false }
    $changed = $false
    try {
        if ($info.StartMode -ne 'Manual') {
            try { Set-Service -Name $Name -StartupType Manual -ErrorAction Stop; $changed = $true } catch { sc.exe config $Name start= demand | Out-Null; $changed = $true }
        }
        if ($info.State -eq 'Running') { Stop-Service -Name $Name -Force -ErrorAction Stop; $changed = $true }
        return $changed
    } catch {
        Write-Log "ERROR: Failed to set service $Name to Manual/stop: $_"
        return $false
    }
}

 # report service status (detailed)
 $svcInfo = Get-ServiceInfo -Name $serviceName
 $svcFull = Get-ServiceFullInfo -Name $serviceName
 if ($svcFull -eq $null) {
    Write-Log "Service ${serviceName}: Not present"
     $serviceNeeds = $false
 } else {
    Write-Output "Name        : $($svcFull.Name)"
    Write-Output "DisplayName : $($svcFull.DisplayName)"
    Write-Output "State       : $($svcFull.State)"
    Write-Output "StartMode   : $($svcFull.StartMode)"
    Write-Output "PathName    : $($svcFull.PathName)"
     # determine if we need to change service when disabling (want Manual)
     $serviceNeeds = $false
     if ($Action -eq 'disable') {
         if ($svcInfo.StartMode -ne 'Manual' -or $svcInfo.State -eq 'Running') { $serviceNeeds = $true }
     } elseif ($Action -eq 'enable') {
         # enable will restore from backup if present, otherwise set to Automatic
         if (Test-Path $serviceBackupReg) { $serviceNeeds = $true } else { if ($svcInfo.StartMode -ne 'Auto' -or $svcInfo.State -ne 'Running') { $serviceNeeds = $true } }
     }
 }


if ($Action -eq 'check') {
    Write-Log "Check-only mode: no changes will be made."
    Write-Log "Done."
    return
}

if ($Action -eq 'disable') {
    $anyChanged = $false
    foreach ($rp in $runPaths) {
        $changed = Backup-And-Remove-RunValue -RunPath $rp
        if ($changed) { $anyChanged = $true }
    }
    # service handling for disable
    if ($svcInfo -ne $null) {
        $svcBacked = Backup-ServiceState -Name $serviceName
        if ($svcBacked) { Write-Log "Backed up service $serviceName state to $serviceBackupReg" }
        $svcChanged = Set-ServiceToManualAndStop -Name $serviceName
        if ($svcChanged) { $anyChanged = $true; Write-Log "Set service $serviceName to Manual and stopped it." }
    }

    if ($anyChanged) {
        Write-Log "Completed disabling DockWorks startup entries and service changes where present."
    } else {
        Write-Log "No DockWorks startup entries or service changes required; nothing to disable."
    }
    Write-Log "Done."
    return
}

if ($Action -eq 'enable') {
    $anyRestored = $false
    foreach ($rp in $runPaths) {
        if (Restore-RunValueFromBackup -RunPath $rp) { $anyRestored = $true }
    }
    # service handling for enable
    if (Test-Path $serviceBackupReg) {
        $svcRestored = Restore-ServiceState -Name $serviceName
        if ($svcRestored) { $anyRestored = $true; Write-Log "Restored service $serviceName from backup." }
    } else {
        # no backup present, try to set to Automatic and start
        $info = Get-ServiceInfo -Name $serviceName
        if ($info -ne $null) {
            try { Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop; Start-Service -Name $serviceName -ErrorAction SilentlyContinue; $anyRestored = $true; Write-Log "Set service ${serviceName} to Automatic and started it." } catch { Write-Log "ERROR: Failed to set/start service ${serviceName}: $_" }
        }
    }

    if ($anyRestored) {
        Write-Log "Completed restoring DockWorks startup entries and service where backups existed."
    } else {
        Write-Log "No backups found or nothing restored."
    }
    Write-Log "Done."
    return
}

