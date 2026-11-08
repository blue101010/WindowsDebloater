<#
.SYNOPSIS
Prohibits Network Bridge on the domain network and requires elevation to set a network location.

.DESCRIPTION
CIS 18.5.11.2 / 18.5.11.4 (L1), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Prohibit installation and configuration of Network Bridge on your DNS domain network = Enabled (NC_AllowNetBridge_NLA = 0)
  Require domain users to elevate when setting a network's location                    = Enabled (NC_StdDomainUserSetLocation = 1)

.NOTES
Windows 11 only; run as Administrator. Both settings only take effect on domain networks.
0205 contains these settings under an incorrect key ("NetworkConnections" without a space),
so it does not configure them.
#>

$scriptName = "0484_Harden_network_connections_policies"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$settings = @(
  @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name = 'NC_AllowNetBridge_NLA'; Kind = 'DWord'; Value = 0 },
  @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name = 'NC_StdDomainUserSetLocation'; Kind = 'DWord'; Value = 1 }
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
