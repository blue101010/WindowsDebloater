<#
.SYNOPSIS
Explicitly sets the SMB server failed-authentication rate limiter to 2000 ms.

.DESCRIPTION
Runs: Set-SmbServerConfiguration -InvalidAuthenticationDelayTimeInMs 2000

.NOTES
- Windows 11 24H2+ (the -InvalidAuthenticationDelayTimeInMs parameter does not exist on older builds; the script stops with an error).
- Requires administrator rights.
- Already the Windows 11 24H2+ default; this pins it so it cannot silently be lowered. Only matters when the machine serves shares.
- Reads the value back with Get-SmbServerConfiguration to confirm it.
- To undo: Set-SmbServerConfiguration -InvalidAuthenticationDelayTimeInMs 2000 (default; 0 disables the limiter)
- Source: 471.md item 3, https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-authentication-rate-limiter
#>

$scriptName = "0473_enforce_smb_failed_authent_rate"
$parameterName = "InvalidAuthenticationDelayTimeInMs"
$targetValue = 2000

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