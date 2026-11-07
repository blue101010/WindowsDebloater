<#
.SYNOPSIS
Disables SMBv3 compression on the SMB server (CVE-2020-0796 "SMBGhost" / CoronaBlue workaround).

.DESCRIPTION
Blocks unauthenticated attackers from exploiting the SMBv3 compression vulnerability
against this machine's SMB server. Sets
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
  DisableCompression = 1 (DWORD)
  0 = compression allowed, 1 = compression disabled.

Only affects clients connecting TO this server. Outbound connections from this machine may
still use compression; install the CVE-2020-0796 security update to fix the client side.
Equivalent Group Policy: Microsoft.Policies.SMBCompression::Pol_SMB_DisableCompression.

.NOTES
- Run as Administrator (writes to HKLM). No reboot required.
- If the Server (LanmanServer) service is not installed, nothing is changed.
- Also disables legitimate SMB compression on newer Windows versions.
- To undo, set DisableCompression to 0.
- Related: 0115_Disabling_SMBv3 Compression_SMBGhost.ps1
- References:
  https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
  https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796
  https://admx.help/?Category=DisableSMBCompression&Policy=Microsoft.Policies.SMBCompression::Pol_SMB_DisableCompression
  https://github.com/technion/DisableSMBCompression
  https://github.com/ollypwn/SMBGhost
#>

$scriptName = "0130_Disabling_SMBv3_Compression_SMBGhost"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$propertyName = "DisableCompression"
$targetValue = 1

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  Write-Host "[$scriptName] [skipped] SMB Server service not installed: $registryPath"
  return
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$propertyName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $targetValue) {
  Set-ItemProperty -Path $registryPath -Name $propertyName -Value $targetValue -Type DWORD -Force -ErrorAction Stop
  $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $propertyName -ErrorAction Stop
if ($confirmedValue -ne $targetValue) {
  throw "[$scriptName] Verification failed: $registryPath $propertyName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $propertyName = $confirmedValue (compression disabled)"
