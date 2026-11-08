$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$testPath = "HKCU:\Software\WindowsDebloater-Test-$([guid]::NewGuid())"

function Assert-Test {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

$registryCases = @(
  @{ File = "0109_Disable_Chrome_RendererCodeIntegrityEnabled.ps1"; Paths = @("HKLM:\SOFTWARE\Policies\Google\Chrome"); Name = "RendererCodeIntegrityEnabled" },
  @{ File = "0110_Disable_Chrome_Offer_to_save_passwords.ps1"; Paths = @("HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Google\ChromeOS"); Name = "PasswordManagerEnabled" },
  @{ File = "0113_Disable_Speech_OneCore_Recognition.ps1"; Paths = @("HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"); Name = "HasAccepted" }
)

try {
  foreach ($case in $registryCases) {
    $source = [IO.File]::ReadAllText((Join-Path $root "security\default\$($case.File)"))
    $index = 0
    foreach ($path in $case.Paths) {
      Assert-Test ($source.Contains('"' + $path + '"')) "$($case.File): missing expected path $path."
      $source = $source.Replace('"' + $path + '"', ('"' + $testPath + '\' + $index + '"'))
      $index++
    }
    $script = [scriptblock]::Create($source)
    foreach ($scenario in @("Missing", "Repeat", "Wrong type")) {
      if ($scenario -eq "Wrong type") {
        for ($i = 0; $i -lt $case.Paths.Count; $i++) {
          New-ItemProperty -LiteralPath "$testPath\$i" -Name $case.Name -Value "0" -PropertyType String -Force | Out-Null
        }
      }
      & $script
      for ($i = 0; $i -lt $case.Paths.Count; $i++) {
        $key = Get-Item -LiteralPath "$testPath\$i"
        try {
          Assert-Test ($key.GetValue($case.Name) -eq 0) "$($case.File): $scenario has wrong value."
          Assert-Test ($key.GetValueKind($case.Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord) "$($case.File): $scenario has wrong type."
        }
        finally { $key.Dispose() }
      }
    }
    Remove-Item -LiteralPath $testPath -Recurse -Force
    Write-Host "[PASS] $($case.File) registry scenarios"
  }
}
finally {
  if (Test-Path -LiteralPath $testPath) { Remove-Item -LiteralPath $testPath -Recurse -Force }
}

function Get-ScheduledTask {
  param($TaskPath, $TaskName, $ErrorAction)
  if ($script:failRead) { throw "Simulated scheduler read failure" }
  if ($TaskName) {
    return @($script:mockTasks | Where-Object { $_.TaskPath -eq $TaskPath -and $_.TaskName -eq $TaskName })
  }
  return $script:mockTasks
}

function Disable-ScheduledTask {
  param($TaskPath, $TaskName, $ErrorAction)
  if ($script:failDisable) { throw "Simulated scheduler write failure" }
  $script:disabled.Add("$TaskPath$TaskName")
  if (-not $script:failVerification) {
    ($script:mockTasks | Where-Object { $_.TaskPath -eq $TaskPath -and $_.TaskName -eq $TaskName }).Settings.Enabled = $false
  }
}

$taskCases = @(
  @{ File = "0123_Disable_Microsoft_Windows_Customer_exp_Improv_Program_sched_task.ps1"; Path = "\Microsoft\Windows\Customer Experience Improvement Program\"; Names = @("BthSQM", "Consolidator", "KernelCeipTask", "Uploader", "UsbCeip") },
  @{ File = "0124_Disable_Microsoft_Windows_Application_Experience_sched_task.ps1"; Path = "\Microsoft\Windows\Application Experience\"; Names = @("AitAgent", "Microsoft Compatibility Appraiser", "ProgramDataUpdater", "StartupAppTask") },
  @{ File = "0125_Disable_Microsoft_Windows_Shell_sched_task.ps1"; Path = "\Microsoft\Windows\Shell\"; Names = @("FamilySafetyUpload", "FamilySafetyMonitor", "FamilySafetyMonitorToastTask", "FamilySafetyRefreshTask") },
  @{ File = "0126_Disable_Microsoft_Windows_SettingSync.ps1"; Path = "\Microsoft\Windows\SettingSync\"; Names = @("BackgroundUploadTask", "CustomTask") }
)

foreach ($case in $taskCases) {
  $scriptPath = Join-Path $root "security\default\$($case.File)"
  $taskScript = [scriptblock]::Create([IO.File]::ReadAllText($scriptPath))
  $script:mockTasks = @($case.Names | ForEach-Object {
    [pscustomobject]@{ TaskPath = $case.Path; TaskName = $_; Settings = [pscustomobject]@{ Enabled = $true } }
  })
  $script:mockTasks += [pscustomobject]@{ TaskPath = "\Other\"; TaskName = $case.Names[0]; Settings = [pscustomobject]@{ Enabled = $true } }
  $script:disabled = New-Object 'System.Collections.Generic.List[string]'
  $script:failRead = $false
  $script:failDisable = $false
  $script:failVerification = $false
  & $taskScript
  Assert-Test ($script:disabled.Count -eq $case.Names.Count) "$($case.File): wrong number of tasks disabled."
  foreach ($name in $case.Names) {
    Assert-Test ($script:disabled.Contains($case.Path + $name)) "$($case.File): missed $name."
  }
  Assert-Test ($script:mockTasks[-1].Settings.Enabled) "$($case.File): modified unrelated task."
  & $taskScript

  $script:mockTasks = @()
  & $taskScript
  foreach ($failure in @("read", "disable", "verification")) {
    $script:mockTasks = @([pscustomobject]@{ TaskPath = $case.Path; TaskName = $case.Names[0]; Settings = [pscustomobject]@{ Enabled = $true } })
    $script:failRead = $failure -eq "read"
    $script:failDisable = $failure -eq "disable"
    $script:failVerification = $failure -eq "verification"
    $threw = $false
    try { & $taskScript } catch { $threw = $true }
    Assert-Test $threw "$($case.File): $failure failure was not surfaced."
  }
  Write-Host "[PASS] $($case.File) mocked scheduler scenarios"
}
