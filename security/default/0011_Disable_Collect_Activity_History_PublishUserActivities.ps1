<#
.SYNOPSIS
Disables the collection of activity history in Windows 10 and Windows 11.

.DESCRIPTION
This script disables publishing activity history in Windows 10 and Windows 11
by setting PublishUserActivities to DWORD 0. Creates the policy key if needed.
Registry access errors stop execution.
If not elevated, requests UAC consent and relaunches as Administrator.

.NOTES
- This script requires administrative privileges to modify the registry.
- For more information about activity history in Windows 10, refer to the following sources:
  - https://www.theregister.co.uk/2018/12/13/windows_10_carry_on_slurping/
  - https://www.howtogeek.com/fyi/windows-10-sends-your-activity-history-to-microsoft-even-if-you-tell-it-not-to/
  - https://www.tenforums.com/tutorials/100341-enable-disable-collect-activity-history-windows-10-a.html#option2
  - https://www.techradar.com/news/windows-10-might-be-recording-and-uploading-your-pcs-activity-history-without-you-knowing

.PARAMETER None
This script does not accept any parameters.

.EXAMPLE
.\0011_Disable_Collect_Activity_History_PublishUserActivities.ps1
Approve the UAC prompt if the current PowerShell session is not elevated.

#>
$principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[0011_Disable_Collect_Activity_History_PublishUserActivities] Requesting administrator privileges through UAC..."
  $executableName = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
  $powerShellExecutable = Join-Path $PSHOME $executableName
  try {
    $elevatedProcess = Start-Process -FilePath $powerShellExecutable -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs -Wait -PassThru -ErrorAction Stop
  }
  catch {
    throw "Administrator elevation failed or was cancelled: $($_.Exception.Message)"
  }
  if ($elevatedProcess.ExitCode -ne 0) {
    throw "The elevated script failed with exit code $($elevatedProcess.ExitCode)."
  }
  return
}

$publishUserActivitiesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path -Path $publishUserActivitiesPath -ErrorAction Stop)) {
  Write-Host "[0011_Disable_Collect_Activity_History_PublishUserActivities] Policy key does not exist. Creating it..."
  New-Item -Path $publishUserActivitiesPath -Force -ErrorAction Stop | Out-Null
}

$publishUserActivitiesValue = Get-ItemProperty -Path $publishUserActivitiesPath -ErrorAction Stop
$property = $publishUserActivitiesValue.PSObject.Properties["PublishUserActivities"]
if ($null -eq $property) {
  Write-Host "[0011_Disable_Collect_Activity_History_PublishUserActivities] PublishUserActivities does not exist. Creating it..."
}
else {
  Write-Host "[0011_Disable_Collect_Activity_History_PublishUserActivities] Initial value of PublishUserActivities: $($property.Value)"
}

if ($null -eq $property -or $property.Value -ne 0) {
  Set-ItemProperty -Path $publishUserActivitiesPath -Name "PublishUserActivities" -Value 0 -Type DWORD -Force -ErrorAction Stop
  $publishUserActivitiesValue = Get-ItemProperty -Path $publishUserActivitiesPath -ErrorAction Stop
  if ($publishUserActivitiesValue.PublishUserActivities -ne 0) {
    throw "PublishUserActivities verification failed: expected 0 after the registry write."
  }
  Write-Host "[0011_Disable_Collect_Activity_History_PublishUserActivities] Updated value of PublishUserActivities: $($publishUserActivitiesValue.PublishUserActivities)"
}
else {
  Write-Host "[0011_Disable_Collect_Activity_History_PublishUserActivities] No change: PublishUserActivities is already set to 0"
}
