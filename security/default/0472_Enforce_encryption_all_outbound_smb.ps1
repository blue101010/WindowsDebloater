<#
.SYNOPSIS
Requires encryption for all outbound SMB connections.

.DESCRIPTION
Runs: Set-SmbClientConfiguration -RequireEncryption $true

.NOTES
- Windows 11 24H2+ (the -RequireEncryption parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Servers without SMB 3.x encryption (older NAS, SMB 2.x devices) are rejected. Run 0476 (audit) first to find incompatible servers.
- Reads the value back with Get-SmbClientConfiguration to confirm it.
- To undo: Set-SmbClientConfiguration -RequireEncryption $false
- Source: 471.md item 2, https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-client-require-encryption
#>

$scriptName = "0472_Enforce_encryption_all_outbound_smb"
$parameterName = "RequireEncryption"
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