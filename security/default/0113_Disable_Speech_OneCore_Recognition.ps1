<#
.SYNOPSIS
Disables the current user's online speech recognition consent setting.
.NOTES
The batch file's unintended trailing space in the registry path has been removed.
https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
#>

$scriptName = "0113_Disable_Speech_OneCore_Recognition"
$path = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
$name = "HasAccepted"

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
