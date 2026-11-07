<#
.SYNOPSIS
Refuses outbound SMB dialects older than SMB 3.1.1.

.DESCRIPTION
Runs: Set-SmbClientConfiguration -Smb2DialectMin 'SMB311'

.NOTES
- Windows 11 24H2+ (the -Smb2DialectMin parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Breaks connections to older NAS/servers that do not negotiate SMB 3.1.1.
- Reads the value back with Get-SmbClientConfiguration to confirm it.
- To undo: Set-SmbClientConfiguration -Smb2DialectMin 'None'
- Source: 471.md item 4, https://learn.microsoft.com/en-us/windows-server/storage/file-server/manage-smb-dialects
#>

$scriptName = "0474_refuse_old_outbound_smb_dialects"
$parameterName = "Smb2DialectMin"
$targetValue = 'SMB311'
$expectedValue = 785  # Get-Smb*Configuration returns the dialect as a number (SMB311 = 0x311)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw "[$scriptName] Must be run as Administrator."
}

if (-not (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue).Parameters.ContainsKey($parameterName)) {
  throw "[$scriptName] Set-SmbClientConfiguration has no -$parameterName parameter on this build (Windows 11 24H2+ required)."
}

$currentValue = (Get-SmbClientConfiguration -ErrorAction Stop).$parameterName
$modified = $false
if ("$currentValue" -ne "$expectedValue") {
  $parameters = @{ $parameterName = $targetValue; Force = $true; Confirm = $false; ErrorAction = "Stop" }
  Set-SmbClientConfiguration @parameters
  $modified = $true
}

$confirmedValue = (Get-SmbClientConfiguration -ErrorAction Stop).$parameterName
if ("$confirmedValue" -ne "$expectedValue") {
  throw "[$scriptName] Verification failed: $parameterName = $confirmedValue; expected $expectedValue ($targetValue)."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status Client $parameterName = $confirmedValue (was $currentValue)"