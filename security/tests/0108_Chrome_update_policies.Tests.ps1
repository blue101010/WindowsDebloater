$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$testKey = "Software\WindowsDebloater-Test-$([guid]::NewGuid())"
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
$testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = "22000" }

function Get-CimInstance {
  param($ClassName, $ErrorAction)
  return $testOS
}

function Assert-Test {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

$cases = @(
  @{ File = "0108.001_Enable_Google_updates_default.ps1"; Name = "UpdateDefault"; Value = 1 },
  @{ File = "0108.002_Set_Google_update_check_period.ps1"; Name = "AutoUpdateCheckPeriodMinutes"; Value = 20 },
  @{ File = "0108.003_Enable_Chrome_updates.ps1"; Name = "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}"; Value = 1 },
  @{ File = "0108.004_Enable_Google_automatic_update_checks.ps1"; Name = "DisableAutoUpdateChecksCheckboxValue"; Value = 0 }
)

try {
  foreach ($case in $cases) {
    $scriptPath = Join-Path $root "security\default\$($case.File)"
    $source = [IO.File]::ReadAllText($scriptPath)
    Assert-Test ($source.Contains('"SOFTWARE\Policies\Google\Update"')) "$($case.File): incorrect policy path."
    Assert-Test ($source.Contains('[Microsoft.Win32.RegistryHive]::LocalMachine')) "$($case.File): incorrect hive."
    $source = $source.Replace('"SOFTWARE\Policies\Google\Update"', ('"' + $testKey + '"'))
    $source = $source.Replace('[Microsoft.Win32.RegistryHive]::LocalMachine', '[Microsoft.Win32.RegistryHive]::CurrentUser')
    $script = [scriptblock]::Create($source)

    foreach ($scenario in @("Missing value", "Repeat run", "Wrong registry type")) {
      if ($scenario -eq "Wrong registry type") {
        $key = $baseKey.OpenSubKey($testKey, $true)
        try { $key.SetValue($case.Name, "$($case.Value)", [Microsoft.Win32.RegistryValueKind]::String) }
        finally { $key.Dispose() }
      }

      & $script
      $key = $baseKey.OpenSubKey($testKey)
      try {
        Assert-Test ($key.GetValue($case.Name) -eq $case.Value) "$($case.File): $scenario produced incorrect data."
        Assert-Test ($key.GetValueKind($case.Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord) "$($case.File): $scenario produced incorrect type."
      }
      finally { $key.Dispose() }
    }

    $testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = "19045" }
    $rejected = $false
    try { & $script } catch { $rejected = $_.Exception.Message -like "*Windows 11 is required*" }
    Assert-Test $rejected "$($case.File): Windows 10 was not rejected."
    $testOS = [pscustomobject]@{ ProductType = 3; BuildNumber = "26100" }
    $rejected = $false
    try { & $script } catch { $rejected = $_.Exception.Message -like "*Windows 11 is required*" }
    Assert-Test $rejected "$($case.File): Windows Server was not rejected."
    $testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = "22000" }
    Write-Host "[PASS] $($case.File)"
  }

  $key = $baseKey.OpenSubKey($testKey)
  try { Assert-Test ($key.GetValueNames().Count -eq $cases.Count) "Unexpected registry values were written." }
  finally { $key.Dispose() }
}
finally {
  $baseKey.DeleteSubKeyTree($testKey, $false)
  $baseKey.Dispose()
}
