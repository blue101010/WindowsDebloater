<#
.SYNOPSIS
Windows 11: restores the classic right-click context menu in Explorer (no "Show more options").

.DESCRIPTION
Sets the default value of
HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32
to an empty string, which masks the Windows 11 context menu COM object for the current user.

.NOTES
Current user only; no administrator rights needed (run it from the account that uses the menu,
not from a different administrator account).
Explorer reads this setting at startup: restart Explorer (or sign out) after a change, or use
-RestartExplorer.
To undo: Remove-Item 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Recurse
https://www.winhelponline.com/blog/get-classic-full-context-menu-windows-11/

.EXAMPLE
.\0289_Misc_Restore_classic_context_menu_Windows_11.ps1 -RestartExplorer
#>
[CmdletBinding()]
param([switch]$RestartExplorer)

$scriptName = '0289_Misc_Restore_classic_context_menu_Windows_11'
$registryPath = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'

function Test-ClassicMenuValue {
  if (-not (Test-Path -LiteralPath $registryPath)) { return $false }
  $key = Get-Item -LiteralPath $registryPath
  return ($key.GetValueNames() -contains '' -and $key.GetValueKind('') -eq 'String' -and $key.GetValue('') -eq '')
}

if (Test-ClassicMenuValue) {
  Write-Host "[$scriptName] [Already configured] Classic context menu value is set ($registryPath)."
}
else {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Set-Item -LiteralPath $registryPath -Value '' -ErrorAction Stop
  if (-not (Test-ClassicMenuValue)) {
    throw "[$scriptName] Verification failed: the InprocServer32 default value is not an empty string."
  }
  Write-Host "[$scriptName] [Was updated] Classic context menu value set ($registryPath)."
}

$explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue |
  Where-Object { $_.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId })
if ($RestartExplorer -and $explorer.Count -gt 0) {
  $explorer | Stop-Process -Force
  Start-Sleep -Seconds 2
  if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
  Write-Host "[$scriptName] Explorer restarted; the classic menu is now active."
}
elseif ($explorer.Count -gt 0) {
  Write-Host "[$scriptName] Restart Explorer to apply: rerun with -RestartExplorer, or sign out and back in."
}
