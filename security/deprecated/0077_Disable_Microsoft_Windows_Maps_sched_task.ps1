
<#
.SYNOPSIS
Disables the Microsoft Windows Maps scheduled tasks and removes the MapsBroker service.

.DESCRIPTION
This script disables the Microsoft Windows Maps scheduled tasks and removes the MapsBroker service. It is typically used as part of a debloating process to remove unnecessary or unwanted features from a Windows 10 system.

.PARAMETER None

.EXAMPLE
.\0077_Disable_Microsoft_Windows_Maps_sched_task.ps1

This example runs the script to disable the MapsUpdateTask and MapsToastTask scheduled tasks, as well as remove the MapsBroker service.

#>
$service = Get-Service -Name "MapsBroker" -ErrorAction SilentlyContinue

if ($service) {
    Write-Output "[0077_Disable_Microsoft_Windows_Maps_sched_task] The MapsBroker service exists and is running. It will be stopped and disabled."
    Stop-Service -Name "MapsBroker" -ErrorAction SilentlyContinue
    Set-Service -Name "MapsBroker" -StartupType Disabled -ErrorAction SilentlyContinue
}
else {
    Write-Output "[0077_Disable_Microsoft_Windows_Maps_sched_task] The MapsBroker service does not exist."
}

$task1 = Get-ScheduledTask -TaskName "MapsUpdateTask" -ErrorAction SilentlyContinue
$task2 = Get-ScheduledTask -TaskName "MapsToastTask" -ErrorAction SilentlyContinue

if ($task1) {
    $task1 | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Write-Output "[0077_Disable_Microsoft_Windows_Maps_sched_task] The MapsUpdateTask scheduled task exists and has been disabled."
}
else {
    Write-Output "[0077_Disable_Microsoft_Windows_Maps_sched_task] The MapsUpdateTask scheduled task does not exist."
}

if ($task2) {
    $task2 | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Write-Output "[0077_Disable_Microsoft_Windows_Maps_sched_task] The MapsToastTask scheduled task exists and has been disabled."
}
else {
    Write-Output "[0077_Disable_Microsoft_Windows_Maps_sched_task] The MapsToastTask scheduled task does not exist."
}