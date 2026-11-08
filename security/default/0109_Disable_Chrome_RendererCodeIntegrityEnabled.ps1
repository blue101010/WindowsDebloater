<#
.SYNOPSIS
Disables Chrome renderer code integrity.
.NOTES
Run as Administrator. This weakens a Chrome security feature; use only if required.
Restart Chrome to apply the policy.
#>

$scriptName = "0109_Disable_Chrome_RendererCodeIntegrityEnabled"
$path = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$name = "RendererCodeIntegrityEnabled"

if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
  New-Item -Path $path -Force -ErrorAction Stop | Out-Null
}
New-ItemProperty -LiteralPath $path -Name $name -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
$key = Get-Item -LiteralPath $path -ErrorAction Stop
try {
  if ($key.GetValue($name) -ne 0 -or $key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
    throw "[$scriptName] Verification failed: $path $name."
  }
}
finally { $key.Dispose() }
Write-Host "[$scriptName] [confirmed] $path $name = 0 (DWORD). Restart Chrome to apply."
