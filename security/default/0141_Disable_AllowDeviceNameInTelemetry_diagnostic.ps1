<#
.SYNOPSIS
Prevents the device name from being sent to Microsoft in Windows diagnostic data.

.DESCRIPTION
Policy: Computer Configuration > Administrative Templates > Windows Components >
Data Collection and Preview Builds > Allow device name to be sent in Windows diagnostic data = Disabled
  HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    AllowDeviceNameInTelemetry (DWORD) = 0

.NOTES
Run as Administrator. Disabled is also the default when the policy is not configured;
this script pins it. The former batch file wrote to SOFTWARE\Microsoft\Windows\DataCollection,
which this policy does not read; the policy key from DataCollection.admx is used instead.
To undo, delete the AllowDeviceNameInTelemetry value.
https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowdevicenameindiagnosticdata
#>

$scriptName = "0141_Disable_AllowDeviceNameInTelemetry_diagnostic"
$registryPath = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$valueName = 'AllowDeviceNameInTelemetry'
$targetValue = 0
$kind = [Microsoft.Win32.RegistryValueKind]::DWord

$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
  $key = $baseKey.CreateSubKey($registryPath)
  if ($null -eq $key) { throw "[$scriptName] Cannot open HKLM:\$registryPath." }
  try {
    $exists = $key.GetValueNames() -contains $valueName
    if ($exists -and $key.GetValueKind($valueName) -eq $kind -and $key.GetValue($valueName) -eq $targetValue) {
      Write-Host "[$scriptName] [Already configured] HKLM:\$registryPath $valueName = $targetValue ($kind)"
      return
    }
    $before = if ($exists) { "$($key.GetValue($valueName)) ($($key.GetValueKind($valueName)))" } else { 'not set' }
    $key.SetValue($valueName, $targetValue, $kind)
    if ($key.GetValueKind($valueName) -ne $kind -or $key.GetValue($valueName) -ne $targetValue) {
      throw "[$scriptName] Verification failed: HKLM:\$registryPath $valueName."
    }
    Write-Host "[$scriptName] [Was updated] HKLM:\$registryPath ${valueName}: $before -> $targetValue ($kind)"
  }
  finally { $key.Dispose() }
}
finally { $baseKey.Dispose() }
