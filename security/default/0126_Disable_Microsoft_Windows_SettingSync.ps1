<#
.SYNOPSIS
Disables registered tasks in the SettingSync Task Scheduler folder.
.NOTES
Run as Administrator. Unlike the batch file, this does not delete task files.
This can affect Windows settings synchronization.
#>

$scriptName = "0126_Disable_Microsoft_Windows_SettingSync"
$taskPath = "\Microsoft\Windows\SettingSync\"
$tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq $taskPath })
if ($tasks.Count -eq 0) {
  Write-Warning "[$scriptName] No registered tasks found in $taskPath"
}
foreach ($task in $tasks) {
  Disable-ScheduledTask -TaskPath $taskPath -TaskName $task.TaskName -ErrorAction Stop | Out-Null
  $confirmed = Get-ScheduledTask -TaskPath $taskPath -TaskName $task.TaskName -ErrorAction Stop
  if ($confirmed.Settings.Enabled -ne $false) { throw "[$scriptName] Verification failed: $taskPath$($task.TaskName) is not confirmed disabled." }
  Write-Host "[$scriptName] [confirmed] Disabled $taskPath$($task.TaskName)"
}
