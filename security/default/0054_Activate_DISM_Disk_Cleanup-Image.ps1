<#
.SYNOPSIS
Removes superseded Windows Update components from the component store (WinSxS) immediately.

.DESCRIPTION
Runs: Dism.exe /Online /Cleanup-Image /StartComponentCleanup

Same cleanup as the scheduled task
"\Microsoft\Windows\Servicing\StartComponentCleanup", except that the task only removes
components superseded for more than 30 days, while this command removes them right away.
Frees disk space after Windows updates.

After cleanup, already-installed updates can still be uninstalled. (The optional
/ResetBase switch, not used here, would also make them permanent.)

.NOTES
- Run as Administrator.
- Can take several minutes.
- Exit codes: 0 = success, 3010 = success, reboot required.
- Reference: https://blog.brankovucinec.com/2014/11/06/use-dism-to-cleanup-winsxs-after-windows-update/
#>

$scriptName = "0054_Activate_DISM_Disk_Cleanup-Image"

Write-Host "[$scriptName] Running DISM component store cleanup (this can take several minutes)..."
& Dism.exe /Online /Cleanup-Image /StartComponentCleanup
$exitCode = $LASTEXITCODE

switch ($exitCode) {
  0 { Write-Host "[$scriptName] [confirmed] Component store cleanup completed." }
  3010 { Write-Host "[$scriptName] [confirmed] Component store cleanup completed. A reboot is required." }
  740 { throw "[$scriptName] DISM requires elevation. Run this script as Administrator." }
  default { throw "[$scriptName] DISM failed with exit code $exitCode. See C:\Windows\Logs\DISM\dism.log." }
}
