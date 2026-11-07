<#
.SYNOPSIS
Disables Search highlights: the illustrations, trending searches and promoted content shown in
the Windows taskbar search box and the search flyout.

.DESCRIPTION
Sets two DWORD values to 0:

1. Policy, all users (Group Policy: Computer Configuration > Administrative Templates >
   Windows Components > Search > "Allow search highlights" = Disabled)
   HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search
     EnableDynamicContentInWSB = 0   (0 = off and locked, 1 / missing = allowed)

2. Current user (Settings > Privacy & security > Search permissions > "Show search highlights")
   HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings
     IsDynamicSearchBoxEnabled = 0   (0 = off, 1 / missing = on)

.NOTES
- Run as Administrator to apply the policy; without it, only the current-user setting is applied.
- Restart Explorer or sign out/in if the search box picture remains.
- Creates keys and values if missing, then reads each value back to confirm it.
- To undo, delete EnableDynamicContentInWSB and set IsDynamicSearchBoxEnabled to 1.
- Related: 0036.02_Disable_cortana_registry_DisableWebSearch.ps1
#>

$scriptName = "0467_disable_search_highlights"
$targets = @(
  @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "EnableDynamicContentInWSB"; RequiresAdmin = $true },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"; Name = "IsDynamicSearchBoxEnabled"; RequiresAdmin = $false }
)
$targetValue = 0

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

foreach ($target in $targets) {
  $registryPath = $target.Path
  $name = $target.Name

  if ($target.RequiresAdmin -and -not $isAdmin) {
    Write-Warning "[$scriptName] [skipped] Not running as Administrator: $registryPath $name not applied."
    continue
  }

  if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $registryPath"
  }

  $property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$name]
  $modified = $false
  if ($null -eq $property -or $property.Value -ne $targetValue) {
    Set-ItemProperty -Path $registryPath -Name $name -Value $targetValue -Type DWORD -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $name -ErrorAction Stop
  if ($confirmedValue -ne $targetValue) {
    throw "[$scriptName] Verification failed: $registryPath $name = $confirmedValue; expected $targetValue."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $registryPath $name = $confirmedValue (disabled)"
}
