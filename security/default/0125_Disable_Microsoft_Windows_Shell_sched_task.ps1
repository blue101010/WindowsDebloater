<#
.SYNOPSIS
Disables the listed Family Safety scheduled tasks.
.NOTES
Run as Administrator. This can affect Microsoft Family Safety functionality.
Tasks absent from this Windows installation are reported.
#>

$scriptName = "0125_Disable_Microsoft_Windows_Shell_sched_task"
$taskPath = "\Microsoft\Windows\Shell\"
$taskNames = @("FamilySafetyUpload", "FamilySafetyMonitor", "FamilySafetyMonitorToastTask", "FamilySafetyRefreshTask")
$tasks = @(Get-ScheduledTask -ErrorAction Stop)
foreach ($name in $taskNames) {
  $task = $tasks | Where-Object { $_.TaskPath -eq $taskPath -and $_.TaskName -eq $name }
  if ($null -eq $task) {
    Write-Warning "[$scriptName] Task not found: $taskPath$name"
    continue
  }
  Disable-ScheduledTask -TaskPath $taskPath -TaskName $name -ErrorAction Stop | Out-Null
  $confirmed = Get-ScheduledTask -TaskPath $taskPath -TaskName $name -ErrorAction Stop
  if ($confirmed.Settings.Enabled -ne $false) { throw "[$scriptName] Verification failed: $taskPath$name is not confirmed disabled." }
  Write-Host "[$scriptName] [confirmed] Disabled $taskPath$name"
}
