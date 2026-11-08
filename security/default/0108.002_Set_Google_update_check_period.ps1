<#
.SYNOPSIS
Sets the minimum interval between automatic Google update checks to 20 minutes.
.NOTES
Windows 11; run as Administrator. This policy affects Google applications, not just Chrome.
https://support.google.com/chrome/a/answer/6350036
#>

$scriptName = "0108.002_Set_Google_update_check_period"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$registryPath = "SOFTWARE\Policies\Google\Update"
$propertyName = "AutoUpdateCheckPeriodMinutes"
$targetValue = 20
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
