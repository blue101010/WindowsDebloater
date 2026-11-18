#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks and prints the CLFS authentication mode (SignDrop exposure check).

.DESCRIPTION
    Read-only check of:
        HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode

    Microsoft's CLFS authentication mitigation is rolled out in stages and is
    controlled by this DWORD value:
        0 = Enforced - every CLFS log file must carry a valid authentication code
        1 = Learning - 90-day learning period
        2 = Disabled by an administrator
        3 = Disabled automatically by the system

    The public SignDrop PoC (improper authentication in clfs.sys .cnpf handling,
    local privilege escalation to SYSTEM) is in scope while Mode is 0 or 1.
    Mode 2 or 3 closes the SignDrop path but switches the CLFS authentication
    mitigation off, which re-exposes the older CLFS memory-corruption bugs the
    mitigation was introduced to stop; Microsoft advises against disabling it.

    Reference: https://github.com/MSNightmare/SignDrop

    This script does not modify the system.
#>

$scriptName = '0494_check_common_log_file_system_authentication_mode'

$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\CLFS\Authentication'
$propertyName = 'Mode'

$modeMeanings = @{
    0 = 'Enforced - CLFS authentication mitigation fully enabled'
    1 = 'Learning - 90-day learning period'
    2 = 'Disabled by an administrator'
    3 = 'Disabled automatically by the system'
}

Write-Host "[$scriptName] Checking $path\$propertyName ..."

if (-not (Test-Path -Path $path -ErrorAction Stop)) {
    Write-Host "[$scriptName] [Status] Registry key not found: $path"
    Write-Host "[$scriptName] [Result] CLFS authentication mitigation is not present on this system; SignDrop exposure check not applicable."
    return
}

$properties = Get-ItemProperty -Path $path -ErrorAction Stop
$property = $properties.PSObject.Properties[$propertyName]

if ($null -eq $property) {
    Write-Host "[$scriptName] [Status] Value '$propertyName' is missing under $path."
    Write-Host "[$scriptName] [Result] CLFS authentication mode is not configured; SignDrop exposure check not applicable."
    return
}

$mode = $property.Value
$modeInt = $mode -as [int]
$typeName = $property.TypeNameOfValue

if ($null -ne $modeInt) {
    $modeHex = '{0:X}' -f $modeInt
    Write-Host "[$scriptName] [Status] $propertyName = $mode (0x$modeHex) [$typeName]"
}
else {
    Write-Host "[$scriptName] [Status] $propertyName = '$mode' [$typeName]"
}

if ($null -eq $modeInt) {
    Write-Host "[$scriptName] [Result] Unexpected non-numeric value; review manually." -ForegroundColor Yellow
    return
}

if ($modeMeanings.ContainsKey($modeInt)) {
    Write-Host "[$scriptName] [Status] Meaning: $($modeMeanings[$modeInt])"
}
else {
    Write-Host "[$scriptName] [Status] Meaning: unknown value"
}

switch ($modeInt) {
    0 {
        Write-Host "[$scriptName] [Result] Mode 0 (Enforced): within the SignDrop exposure scope (Mode 0 or 1)." -ForegroundColor Red
    }
    1 {
        Write-Host "[$scriptName] [Result] Mode 1 (Learning): within the SignDrop exposure scope (Mode 0 or 1)." -ForegroundColor Red
    }
    2 {
        Write-Host "[$scriptName] [Result] Mode 2 (Disabled by administrator): not exposed to SignDrop, but the CLFS authentication mitigation is off and older CLFS memory-corruption bugs are re-exposed; Microsoft advises against disabling it." -ForegroundColor Yellow
    }
    3 {
        Write-Host "[$scriptName] [Result] Mode 3 (Disabled automatically by the system): not exposed to SignDrop, but the CLFS authentication mitigation is off and older CLFS memory-corruption bugs are re-exposed." -ForegroundColor Yellow
    }
    default {
        Write-Host "[$scriptName] [Result] Unknown Mode value $modeInt; review manually." -ForegroundColor Yellow
    }
}
