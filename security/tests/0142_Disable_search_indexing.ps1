<#
.SYNOPSIS
Disables Windows Search indexing (WSearch service) and optionally deletes the search index.

.DESCRIPTION
Stops the Windows Search service and sets its startup type to Disabled.
With -DeleteIndex, also deletes the index database: Windows.edb (Windows 10) or
Windows.db (SQLite format used by Windows 11).

.NOTES
Kept in security\tests: this is not a security control, and disabling indexing slows down
Start menu, File Explorer and Settings searches, and breaks classic Outlook instant search.
Run as Administrator.
To undo: Set-Service WSearch -StartupType Automatic; Start-Service WSearch
(the index is rebuilt automatically).
Source: https://github.com/AcaplaStd/WindowsConfigurator/blob/master/doit.cmd

.EXAMPLE
.\0142_Disable_search_indexing.ps1 -DeleteIndex
#>
param([switch]$DeleteIndex)

$scriptName = "0142_Disable_search_indexing"
$serviceName = 'WSearch'

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
  Write-Host "[$scriptName] [Already configured] Service $serviceName is not installed."
}
else {
  if ($service.StartType -eq 'Disabled') {
    Write-Host "[$scriptName] [Already configured] Service $serviceName startup type = Disabled"
  }
  else {
    $before = $service.StartType
    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
    if ((Get-Service -Name $serviceName).StartType -ne 'Disabled') {
      throw "[$scriptName] Verification failed: $serviceName startup type is not Disabled."
    }
    Write-Host "[$scriptName] [Was updated] Service $serviceName startup type: $before -> Disabled"
  }

  $service = Get-Service -Name $serviceName
  if ($service.Status -eq 'Stopped') {
    Write-Host "[$scriptName] [Already configured] Service $serviceName status = Stopped"
  }
  else {
    $before = $service.Status
    Stop-Service -Name $serviceName -Force -ErrorAction Stop
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    Write-Host "[$scriptName] [Was updated] Service $serviceName status: $before -> Stopped"
  }
}

if ($DeleteIndex) {
  $indexDir = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows'
  foreach ($name in 'Windows.edb', 'Windows.db') {
    $file = Join-Path $indexDir $name
    if (-not (Test-Path -LiteralPath $file -ErrorAction Stop)) {
      Write-Host "[$scriptName] [Already configured] Index file not present: $file"
      continue
    }
    Remove-Item -LiteralPath $file -Force -ErrorAction Stop
    Write-Host "[$scriptName] [Was updated] Deleted index file: $file"
  }
}
