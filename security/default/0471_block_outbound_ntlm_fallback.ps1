<#
.SYNOPSIS
Blocks NTLM fallback for outbound SMB connections (SMB client uses Kerberos/PKU2U only).

.DESCRIPTION
Runs: Set-SmbClientConfiguration -BlockNTLM $true

.NOTES
- Windows 11 24H2+ (the -BlockNTLM parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Connections to servers reachable only with NTLM (IP-address paths, workgroup/NAS shares, local accounts) will fail. Pilot first; per-server exceptions can be set with Set-SmbClientConfiguration -BlockNTLMServerExceptionList.
- Reads the value back with Get-SmbClientConfiguration to confirm it.
- To undo: Set-SmbClientConfiguration -BlockNTLM $false
- Source: 471.md item 1, https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking
#>

$scriptName = "0471_block_outbound_ntlm_fallback"
$parameterName = "BlockNTLM"
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