<#
.SYNOPSIS
Audits outbound SMB connections to servers that do not support encryption.

.DESCRIPTION
Runs: Set-SmbClientConfiguration -AuditServerDoesNotSupportEncryption $true

.NOTES
- Windows 11 24H2+ (the -AuditServerDoesNotSupportEncryption parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Audit only, no connection is blocked. Events go to Microsoft-Windows-SMBClient/Audit. Use before 0472.
- Reads the value back with Get-SmbClientConfiguration to confirm it.
- To undo: Set-SmbClientConfiguration -AuditServerDoesNotSupportEncryption $false
- Source: 471.md item 6, https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview#smb-signing-and-encryption-auditing
#>

$scriptName = "0476_audit_outbound_smb_encryption_unsupported"
$parameterName = "AuditServerDoesNotSupportEncryption"
$targetValue = $true

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw "[$scriptName] Must be run as Administrator."
}

if (-not (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue).Parameters.ContainsKey($parameterName)) {
  throw "[$scriptName] Set-SmbClientConfiguration has no -$parameterName parameter on this build (Windows 11 24H2+ required)."
}

$currentValue = (Get-SmbClientConfiguration -ErrorAction Stop).$parameterName
$modified = $false
if ("$currentValue" -ne "$targetValue") {
  $parameters = @{ $parameterName = $targetValue; Force = $true; Confirm = $false; ErrorAction = "Stop" }
  Set-SmbClientConfiguration @parameters
  $modified = $true
}

$confirmedValue = (Get-SmbClientConfiguration -ErrorAction Stop).$parameterName
if ("$confirmedValue" -ne "$targetValue") {
  throw "[$scriptName] Verification failed: $parameterName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status Client $parameterName = $confirmedValue (was $currentValue)"