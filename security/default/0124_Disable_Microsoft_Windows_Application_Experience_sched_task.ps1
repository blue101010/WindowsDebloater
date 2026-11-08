<#
.SYNOPSIS
Disables the listed Application Experience scheduled tasks.
.NOTES
Run as Administrator. Tasks absent from this Windows installation are reported.
#>

$scriptName = "0124_Disable_Microsoft_Windows_Application_Experience_sched_task"
$taskPath = "\Microsoft\Windows\Application Experience\"
$taskNames = @("AitAgent", "Microsoft Compatibility Appraiser", "ProgramDataUpdater", "StartupAppTask")
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
