<#
.SYNOPSIS
Disables the listed Customer Experience Improvement Program scheduled tasks.
.NOTES
Run as Administrator. Tasks absent from this Windows installation are reported.
#>

$scriptName = "0123_Disable_Microsoft_Windows_Customer_exp_Improv_Program_sched_task"
$taskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
$taskNames = @("BthSQM", "Consolidator", "KernelCeipTask", "Uploader", "UsbCeip")
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
