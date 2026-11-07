<#
.SYNOPSIS
Refuses inbound SMB dialects older than SMB 3.1.1 on the SMB server.

.DESCRIPTION
Runs: Set-SmbServerConfiguration -Smb2DialectMin 'SMB311'

.NOTES
- Windows 11 24H2+ (the -Smb2DialectMin parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Clients that cannot negotiate SMB 3.1.1 can no longer reach this machine's shares. Pilot clients before enforcing.
- Reads the value back with Get-SmbServerConfiguration to confirm it.
- To undo: Set-SmbServerConfiguration -Smb2DialectMin 'None'
- Source: 471.md item 5, https://learn.microsoft.com/en-us/windows-server/storage/file-server/manage-smb-dialects
#>

$scriptName = "0475_refuse_old_inbound_smb_dialects"
$parameterName = "Smb2DialectMin"
$targetValue = 'SMB311'
$expectedValue = 785  # Get-Smb*Configuration returns the dialect as a number (SMB311 = 0x311)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw "[$scriptName] Must be run as Administrator."
}

if (-not (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue).Parameters.ContainsKey($parameterName)) {
  throw "[$scriptName] Set-SmbServerConfiguration has no -$parameterName parameter on this build (Windows 11 24H2+ required)."
}

$currentValue = (Get-SmbServerConfiguration -ErrorAction Stop).$parameterName
$modified = $false
if ("$currentValue" -ne "$expectedValue") {
  $parameters = @{ $parameterName = $targetValue; Force = $true; Confirm = $false; ErrorAction = "Stop" }
  Set-SmbServerConfiguration @parameters
  $modified = $true
}

$confirmedValue = (Get-SmbServerConfiguration -ErrorAction Stop).$parameterName
if ("$confirmedValue" -ne "$expectedValue") {
  throw "[$scriptName] Verification failed: $parameterName = $confirmedValue; expected $expectedValue ($targetValue)."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status Server $parameterName = $confirmedValue (was $currentValue)"