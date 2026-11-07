<#
.SYNOPSIS
Enables User Account Control (UAC) and requires credentials for every elevation prompt.

.DESCRIPTION
Sets these DWORD values under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.
EnableLUA is named after "Limited User Account", the former name of UAC.

  EnableLUA = 1
    0 = UAC disabled, 1 = UAC enabled (default). Enforce and keep at 1.

  ConsentPromptBehaviorAdmin = 3 (administrators)
    0 = Elevate without prompting
    1 = Prompt for credentials on the secure desktop
    2 = Prompt for consent on the secure desktop
    3 = Prompt for credentials            <-- set by this script
    4 = Prompt for consent
    5 = Prompt for consent for non-Windows binaries (default)

  ConsentPromptBehaviorUser = 3 (standard users)
    0 = Automatically deny elevation requests
    1 = Prompt for credentials on the secure desktop
    3 = Prompt for credentials (default)  <-- set by this script

.NOTES
- Run as Administrator (writes to HKLM).
- A change to EnableLUA takes effect after a reboot.
- Creates the key and values if missing, then reads each value back to confirm it.
- References:
  https://support.gfi.com/hc/en-us/articles/360012968753-How-to-disable-User-Account-Control-UAC-
  https://gallery.technet.microsoft.com/scriptcenter/Disable-UAC-using-730b6ecd
#>

$scriptName = "0129_Enable_UAC_User_Account_Control"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$targetValues = [ordered]@{
  EnableLUA                  = 1
  ConsentPromptBehaviorAdmin = 3
  ConsentPromptBehaviorUser  = 3
}

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
  New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
  Write-Host "[$scriptName] Created registry path: $registryPath"
}

foreach ($name in $targetValues.Keys) {
  $targetValue = $targetValues[$name]
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
  Write-Host "[$scriptName] [confirmed] $status $registryPath $name = $confirmedValue"
}
