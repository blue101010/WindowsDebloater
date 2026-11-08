$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot '..\default\0481_Enable_Defender_email_scanning.ps1'
$source = [IO.File]::ReadAllText((Resolve-Path $file))
$productionPath = 'SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
$testPath = 'Software\WindowsDebloater-Test-' + [guid]::NewGuid()
if (-not $source.Contains('"' + $productionPath + '"')) { throw 'Incorrect production policy path.' }
if (-not $source.Contains('[Microsoft.Win32.RegistryHive]::LocalMachine')) { throw 'Incorrect production registry hive.' }
$source = $source.Replace('"' + $productionPath + '"', '"' + $testPath + '"')
$source = $source.Replace('[Microsoft.Win32.RegistryHive]::LocalMachine', '[Microsoft.Win32.RegistryHive]::CurrentUser')
$scriptBlock = [scriptblock]::Create($source)
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
$testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = '22000' }

function Get-CimInstance {
  param($ClassName, $ErrorAction)
  return $testOS
}

try {
  foreach ($scenario in @('Missing', 'Repeat', 'Wrong type')) {
    if ($scenario -eq 'Wrong type') {
      $key = $baseKey.OpenSubKey($testPath, $true)
      try { $key.SetValue('DisableEmailScanning', '0', [Microsoft.Win32.RegistryValueKind]::String) }
      finally { $key.Dispose() }
    }
    $output = @(& $scriptBlock 6>&1 | ForEach-Object { "$_" }) -join "`n"
    $expectedStatus = if ($scenario -eq 'Repeat') { '[Already configured]' } else { '[Was updated]' }
    if (-not $output.Contains($expectedStatus) -or $output.Contains('confirmed')) {
      throw "$scenario printed an unexpected status: $output"
    }
    $key = $baseKey.OpenSubKey($testPath)
    try {
      if ($key.GetValue('DisableEmailScanning') -ne 0 -or $key.GetValueKind('DisableEmailScanning') -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        throw "$scenario did not set the expected DWORD."
      }
    }
    finally { $key.Dispose() }
  }
  $baseKey.DeleteSubKeyTree($testPath, $false)
  foreach ($os in @(
    [pscustomobject]@{ ProductType = 1; BuildNumber = '19045' },
    [pscustomobject]@{ ProductType = 3; BuildNumber = '26100' }
  )) {
    $testOS = $os
    $rejected = $false
    try { & $scriptBlock } catch { $rejected = $_.Exception.Message -like '*Windows 11 is required*' }
    if (-not $rejected) { throw 'Unsupported Windows version was not rejected.' }
    $key = $baseKey.OpenSubKey($testPath)
    if ($null -ne $key) {
      $key.Dispose()
      throw 'Unsupported Windows version created a registry key.'
    }
  }
  Write-Host '[PASS] Registry data, type, repeat runs, and Windows version checks.'
}
finally {
  $baseKey.DeleteSubKeyTree($testPath, $false)
  $baseKey.Dispose()
}
