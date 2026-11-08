<#
.SYNOPSIS
Requires a TPM + PIN pre-boot authentication for BitLocker on the operating system drive.

.DESCRIPTION
CIS 18.9.11.2.x (BL), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Require additional authentication at startup = Enabled (UseAdvancedStartup = 1)
    Allow BitLocker without a compatible TPM  = False                                    (EnableBDEWithNoTPM = 0)
    Configure TPM startup                     = Do not allow TPM                         (UseTPM = 0)
    Configure TPM startup PIN                 = Require startup PIN with TPM             (UseTPMPIN = 1)
    Configure TPM startup key                 = Do not allow startup key with TPM        (UseTPMKey = 0)
    Configure TPM startup key and PIN         = Do not allow startup key and PIN with TPM (UseTPMKeyPIN = 0)

.NOTES
Windows 11 only; run as Administrator. HIGH IMPACT: a PIN is required at every boot,
unattended restarts stop at the PIN prompt, and BitLocker cannot be enabled without
adding a TPM+PIN protector (for example: manage-bde -protectors -add C: -TPMAndPIN).
Existing TPM-only protectors are not changed by this policy.
https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure
#>

$scriptName = "0489_Require_BitLocker_startup_PIN"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$settings = @(
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseAdvancedStartup'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'EnableBDEWithNoTPM'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPM'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPMPIN'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPMKey'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPMKeyPIN'; Kind = 'DWord'; Value = 0 }
)

$hive = [Microsoft.Win32.RegistryHive]::LocalMachine
$basePath = ''
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
try {
  foreach ($setting in $settings) {
    $path = $basePath + $setting.Path
    $kind = [Microsoft.Win32.RegistryValueKind]$setting.Kind
    $key = $baseKey.CreateSubKey($path)
    if ($null -eq $key) { throw "[$scriptName] Cannot open HKLM:\$path." }
    try {
      $display = if ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { "$(@($setting.Value).Count) value(s)" } else { "$($setting.Value)" }
      $current = $null
      $currentKind = $null
      if ($key.GetValueNames() -contains $setting.Name) {
        $current = $key.GetValue($setting.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $currentKind = $key.GetValueKind($setting.Name)
      }
      if ($currentKind -eq $kind -and (@($current) -join '|') -eq (@($setting.Value) -join '|')) {
        Write-Host "[$scriptName] [Already configured] HKLM:\$path $($setting.Name) = $display ($kind)"
        continue
      }
      $before = if ($null -eq $currentKind) { 'not set' } elseif ($currentKind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { "$(@($current).Count) value(s) ($currentKind)" } else { "$current ($currentKind)" }
      $key.SetValue($setting.Name, $setting.Value, $kind)
      $actual = $key.GetValue($setting.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if ($key.GetValueKind($setting.Name) -ne $kind -or (@($actual) -join '|') -ne (@($setting.Value) -join '|')) {
        throw "[$scriptName] Verification failed: HKLM:\$path $($setting.Name)."
      }
      Write-Host "[$scriptName] [Was updated] HKLM:\$path $($setting.Name): $before -> $display ($kind)"
    }
    finally { $key.Dispose() }
  }
}
finally { $baseKey.Dispose() }
