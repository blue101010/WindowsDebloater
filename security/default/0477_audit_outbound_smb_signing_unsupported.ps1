<#
.SYNOPSIS
Audits outbound SMB connections to servers that do not support signing.

.DESCRIPTION
Runs: Set-SmbClientConfiguration -AuditServerDoesNotSupportSigning $true

.NOTES
- Windows 11 24H2+ (the -AuditServerDoesNotSupportSigning parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Audit only, no connection is blocked. Events go to Microsoft-Windows-SMBClient/Audit. Complements signing enforcement (0343).
- Reads the value back with Get-SmbClientConfiguration to confirm it.
- To undo: Set-SmbClientConfiguration -AuditServerDoesNotSupportSigning $false
- Source: 471.md item 7, https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview#smb-signing-and-encryption-auditing
#>

$scriptName = "0477_audit_outbound_smb_signing_unsupported"
$parameterName = "AuditServerDoesNotSupportSigning"
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