<#
.SYNOPSIS
Disables the password manager offer using Chrome and ChromeOS policy values.
.NOTES
Run as Administrator. The ChromeOS registry key is retained from the batch file;
it is not a Windows Chrome policy. Restart Chrome to apply the Chrome policy.
https://admx.help/?Category=ChromeOS&Policy=Google.Policies.ChromeOS::PasswordManagerEnabled
#>

$scriptName = "0110_Disable_Chrome_Offer_to_save_passwords"
$name = "PasswordManagerEnabled"
foreach ($path in @("HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Google\ChromeOS")) {
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
  Write-Host "[$scriptName] [confirmed] $path $name = 0 (DWORD)"
}
Write-Host "[$scriptName] Restart Chrome to apply the policy."
