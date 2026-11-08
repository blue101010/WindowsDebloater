<#
.SYNOPSIS
Keeps local firewall and connection security rules applied on the Domain and Private profiles.

.DESCRIPTION
CIS 9.1.x / 9.2.x (L1), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Windows Firewall: Domain/Private: Settings: Apply local firewall rules             = Yes (AllowLocalPolicyMerge = 1)
  Windows Firewall: Domain/Private: Settings: Apply local connection security rules  = Yes (AllowLocalIPsecPolicyMerge = 1)

.NOTES
Windows 11 only; run as Administrator. The Public profile values are configured by
0205_Configure_CIS_Windows10_V181_DSC_hardening.ps1 (set to 0 there).
https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
#>

$scriptName = "0483_Enforce_firewall_local_rule_merge_domain_private"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$settings = @(
  @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'AllowLocalPolicyMerge'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'AllowLocalIPsecPolicyMerge'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'AllowLocalPolicyMerge'; Kind = 'DWord'; Value = 1 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'AllowLocalIPsecPolicyMerge'; Kind = 'DWord'; Value = 1 }
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
