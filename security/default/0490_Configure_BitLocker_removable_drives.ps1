<#
.SYNOPSIS
Applies the CIS BitLocker policy for removable data drives.

.DESCRIPTION
CIS 18.9.11.3.x (BL), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Choose how removable drives can be recovered (RDVRecovery is set by 0133/0134):
    Recovery Password                         = Do not allow 48-digit recovery password (RDVRecoveryPassword = 0)
    Recovery Key                              = Do not allow 256-bit recovery key       (RDVRecoveryKey = 0)
    Omit recovery options from setup wizard   = True                                    (RDVHideRecoveryPage = 1)
    Save recovery information to AD DS        = False                                   (RDVActiveDirectoryBackup = 0)
    Storage of recovery information to AD DS  = Backup recovery passwords and key packages (RDVActiveDirectoryInfoToStore = 1)
    Do not enable BitLocker until AD DS backup = False                                  (RDVRequireActiveDirectoryBackup = 0)
  Configure use of passwords for removable data drives = Disabled                       (RDVPassphrase = 0)
  Require use of smart cards on removable data drives  = True                           (RDVEnforceUserCert = 1)
  Deny write access to removable drives not protected by BitLocker = Enabled            (RDVDenyWriteAccess = 1)

.NOTES
Windows 11 only; run as Administrator. HIGH IMPACT: USB drives become read-only until
encrypted with BitLocker To Go, and encryption requires a smart card. Values follow the CIS
benchmark; 0181's text for RDVActiveDirectoryInfoToStore and RDVRequireActiveDirectoryBackup
was inconsistent with CIS.
https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure
#>

$scriptName = "0490_Configure_BitLocker_removable_drives"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$settings = @(
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVRecoveryPassword'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVRecoveryKey'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVHideRecoveryPage'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVActiveDirectoryBackup'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVActiveDirectoryInfoToStore'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVRequireActiveDirectoryBackup'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVPassphrase'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\FVE'; Name = 'RDVEnforceUserCert'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SYSTEM\CurrentControlSet\Policies\Microsoft\FVE'; Name = 'RDVDenyWriteAccess'; Kind = 'DWord'; Value = 1 }
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
