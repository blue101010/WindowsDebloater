<#
.SYNOPSIS
Enforces NTLMv2-only authentication by setting LAN Manager compatibility level to 5.

.DESCRIPTION
This script sets 'LmCompatibilityLevel' to 5 under the LSA registry key, which
configures Windows to send NTLMv2 responses only and refuse both LM and NTLM
authentication requests.

CIS Benchmark: CIS Microsoft Windows 10/11 - Level 1
Control:       2.3.11.7 (L1) Network security: LAN Manager authentication level
               Send NTLMv2 response only. Refuse LM & NTLM.

It reports the current state before making any change, and only writes to the
registry if the value is not already set correctly.

.PARAMETER None

.EXAMPLE
.\0463_Enforce_NTLMv2_only_LmCompatibilityLevel.ps1
This command runs the script and enforces NTLMv2-only LAN Manager authentication.

.NOTES
Registry:   HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
Value:      LmCompatibilityLevel = 5 (DWORD)
            0 = Send LM & NTLM responses
            1 = Send LM & NTLM; use NTLMv2 session security if negotiated
            2 = Send NTLM response only
            3 = Send NTLMv2 response only
            4 = Send NTLMv2 response only; refuse LM
            5 = Send NTLMv2 response only; refuse LM & NTLM  <-- CIS L1 required
Applies to: Windows 10 / Windows 11
Risk:       Prevents LM/NTLM downgrade attacks (Pass-the-Hash, relay attacks).
#>

# Enforce NTLMv2-only authentication (LAN Manager authentication level = 5)

# Elevation check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host '[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] This script requires elevation. Relaunching as Administrator in 3 seconds...'
  Start-Sleep -Seconds 3
  try {
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction Stop
    exit
  }
  catch {
    Write-Warning "[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] Elevation failed or was denied: $_"
    Write-Host '[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] Please re-run this script as Administrator manually.'
    Read-Host 'Press Enter to close...'
    exit 1
  }
}

$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$propertyName = 'LmCompatibilityLevel'
$desiredValue = 5
$exitCode     = 0

try {
  # Read current state
  $currentEntry = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

  if ($null -eq $currentEntry) {
    Write-Host '[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] Current state : LmCompatibilityLevel does not exist (Windows default allows LM/NTLM).'
  }
  else {
    Write-Host "[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] Current state : LmCompatibilityLevel = $($currentEntry.LmCompatibilityLevel)"
  }

  # Apply only if needed
  if ($null -eq $currentEntry -or $currentEntry.LmCompatibilityLevel -ne $desiredValue) {
    New-ItemProperty -Path $registryPath `
                     -Name $propertyName `
                     -Value $desiredValue `
                     -PropertyType DWord `
                     -Force | Out-Null

    # Verify the write succeeded
    $written = (Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($written -eq $desiredValue) {
      Write-Host "[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] CHANGED : LmCompatibilityLevel set to $desiredValue (NTLMv2 only; LM & NTLM refused) - verified."
    }
    else {
      Write-Warning "[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] FAILED  : LmCompatibilityLevel could not be verified (read back: $written)."
      $exitCode = 1
    }
  }
  else {
    Write-Host "[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] No change : LmCompatibilityLevel is already $desiredValue."
  }

  if ($exitCode -eq 0) {
    Write-Host '[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] A reboot may be required for full effect.'
  }
}
catch {
  Write-Warning "[0463_Enforce_NTLMv2_only_LmCompatibilityLevel] Unexpected error: $_"
  $exitCode = 1
}
finally {
  Read-Host 'Press Enter to close...'
}

exit $exitCode
