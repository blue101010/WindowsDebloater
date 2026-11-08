<#
.SYNOPSIS
Configures how BitLocker-protected operating system drives can be recovered.

.DESCRIPTION
CIS 18.9.11.2.x (BL), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Choose how BitLocker-protected operating system drives can be recovered = Enabled (OSRecovery = 1)
    Allow data recovery agent                                = False                            (OSManageDRA = 0)
    Recovery Password                                        = Allow 48-digit recovery password (OSRecoveryPassword = 2)
    Recovery Key                                             = Allow 256-bit recovery key       (OSRecoveryKey = 2)
    Omit recovery options from the BitLocker setup wizard    = True                             (OSHideRecoveryPage = 1)

.NOTES
Windows 11 only; run as Administrator. Applies when BitLocker is next enabled on the OS drive.
Values follow the CIS benchmark (as in 0133/0134); 0181's text for the recovery password and
key options was inconsistent with CIS.
Hiding recovery options means the wizard will not offer to save or print the recovery key;
make sure recovery information is backed up elsewhere (Microsoft account, Entra ID or AD DS).
https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure
#>

$scriptName = "0488_Configure_BitLocker_OS_drive_recovery"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$settings = @(
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'OSRecovery'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'OSManageDRA'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'OSRecoveryPassword'; Kind = 'DWord'; Value = 2 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'OSRecoveryKey'; Kind = 'DWord'; Value = 2 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'OSHideRecoveryPage'; Kind = 'DWord'; Value = 1 }
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
