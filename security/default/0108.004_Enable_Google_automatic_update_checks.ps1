<#
.SYNOPSIS
Sets the legacy DisableAutoUpdateChecksCheckboxValue setting to 0.
.NOTES
Windows 11; run as Administrator. This preserves a legacy setting from the batch file;
its effect on current Google Updater versions is not established.
https://support.google.com/chrome/a/answer/6350036
#>

$scriptName = "0108.004_Enable_Google_automatic_update_checks"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$registryPath = "SOFTWARE\Policies\Google\Update"
$propertyName = "DisableAutoUpdateChecksCheckboxValue"
$targetValue = 0
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
  $key = $baseKey.CreateSubKey($registryPath)
  if ($null -eq $key) { throw "[$scriptName] Cannot open registry key: HKLM:\$registryPath" }
  try {
    $key.SetValue($propertyName, $targetValue, [Microsoft.Win32.RegistryValueKind]::DWord)
    if ($key.GetValue($propertyName) -ne $targetValue -or $key.GetValueKind($propertyName) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
      throw "[$scriptName] Verification failed for $propertyName."
    }
    Write-Host "[$scriptName] [confirmed] HKLM:\$registryPath $propertyName = $targetValue (DWORD)"
  }
  finally { $key.Dispose() }
}
finally { $baseKey.Dispose() }
