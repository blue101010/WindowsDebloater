<#
.SYNOPSIS
Disables WDigest credential storage in memory.

.DESCRIPTION
Sets UseLogonCredential to 0 under
HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.

.NOTES
- Run as Administrator (writes to HKLM).
- Creates the registry key and value if missing, then verifies the value.
- References:
  https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a
  https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/
  https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-72753
#>

$scriptName = "0127_Disable_Wdigest_UseLogonCredential"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$propertyName = "UseLogonCredential"
$targetValue = 0

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Write-Host "[$scriptName] Created registry path: $registryPath"
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$propertyName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $targetValue) {
  New-ItemProperty -Path $registryPath -Name $propertyName -Value $targetValue -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
  $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $propertyName -ErrorAction Stop
if ($confirmedValue -ne $targetValue) {
  throw "[$scriptName] Verification failed: $registryPath $propertyName = $confirmedValue; expected $targetValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $propertyName = $confirmedValue (WDigest credential storage disabled)"
