<#
.SYNOPSIS
Audits inbound SMB clients that do not support encryption.

.DESCRIPTION
Runs: Set-SmbServerConfiguration -AuditClientDoesNotSupportEncryption $true

.NOTES
- Windows 11 24H2+ (the -AuditClientDoesNotSupportEncryption parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Audit only, no connection is blocked. Events go to Microsoft-Windows-SMBServer/Audit. Only matters when the machine serves shares.
- Reads the value back with Get-SmbServerConfiguration to confirm it.
- To undo: Set-SmbServerConfiguration -AuditClientDoesNotSupportEncryption $false
- Source: 471.md item 8, https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview#smb-signing-and-encryption-auditing
#>

$scriptName = "0478_audit_inbound_smb_encryption_unsupported"
$parameterName = "AuditClientDoesNotSupportEncryption"
$targetValue = $true

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw "[$scriptName] Must be run as Administrator."
}

if (-not (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue).Parameters.ContainsKey($parameterName)) {
  throw "[$scriptName] Set-SmbServerConfiguration has no -$parameterName parameter on this build (Windows 11 24H2+ required)."
}

$currentValue = (Get-SmbServerConfiguration -ErrorAction Stop).$parameterName
$modified = $false
if ("$currentValue" -ne "$targetValue") {
  $parameters = @{ $parameterName = $targetValue; Force = $true; Confirm = $false; ErrorAction = "Stop" }
  Set-SmbServerConfiguration @parameters
  $modified = $true
}

$confirmedValue = (Get-SmbServerConfiguration -ErrorAction Stop).$parameterName
if ("$confirmedValue" -ne "$targetValue") {
  throw "[$scriptName] Verification failed: $parameterName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status Server $parameterName = $confirmedValue (was $currentValue)"