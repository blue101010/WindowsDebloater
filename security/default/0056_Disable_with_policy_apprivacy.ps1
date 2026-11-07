<#
.SYNOPSIS
Denies Windows apps access to personal data and device features through the AppPrivacy policy.

.DESCRIPTION
Equivalent to the Group Policy "Computer Configuration > Administrative Templates >
Windows Components > App Privacy > Let Windows apps access ..." settings, set to "Force Deny".

1. HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy
   Sets each LetApps* value below to 2 for all users:
     0 = User is in control (default, Settings app toggle applies)
     1 = Force Allow
     2 = Force Deny (apps cannot access it; the Settings toggle is greyed out)
   Values affected:
     LetAppsAccessAccountInfo     - account name, picture and info
     LetAppsAccessCalendar        - calendar
     LetAppsAccessCallHistory     - call history
     LetAppsAccessContacts        - contacts
     LetAppsAccessEmail           - email
     LetAppsAccessLocation        - location
     LetAppsAccessMessaging       - messages (SMS/MMS)
     LetAppsAccessMotion          - motion sensor data
     LetAppsAccessNotifications   - notifications
     LetAppsAccessRadios          - radio control (Bluetooth, Wi-Fi, cellular on/off)
     LetAppsAccessTrustedDevices  - paired/trusted devices
     LetAppsSyncWithDevices       - sync with unpaired wireless devices (beacons, etc.)
     LetAppsAccessMicrophone      - microphone
     LetAppsAccessCamera          - camera

2. HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass
   Sets UserAuthPolicy to 2. This value controls which devices may connect to this PC
   through Xbox SmartGlass / connected-device experiences.

3. HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\<app SID>\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}
   Sets Value to "Deny" for the current user: blocks contacts access for the single
   app container identified by that SID. This legacy DeviceAccess location is only used
   by Windows versions before 1903; newer builds use CapabilityAccessManager\ConsentStore.

.NOTES
- Run as Administrator (sections 1 and 2 write to HKLM).
- Missing registry keys and values are created; every value is read back to confirm it.
- Section 3 is skipped on Windows 10 1903 (build 18362) and later, where it has no effect.
- To undo section 1, delete the LetApps* values (or set them to 0) and restart apps.
#>

Write-Output "[0056_Disable_with_policy_apprivacy] Force-deny app access to personal data and devices (AppPrivacy policy)"

$scriptName = "0056_Disable_with_policy_apprivacy"
$appPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$smartGlassPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass"
$deviceAccessPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}"

function Set-ConfirmedRegistryValue {
  param (
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)]$Value,
    [Parameter(Mandatory = $true)][ValidateSet("DWORD", "String")][string]$Type
  )

  if (-not (Test-Path -Path $Path -ErrorAction Stop)) {
    New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $Path"
  }

  $property = (Get-ItemProperty -Path $Path -ErrorAction Stop).PSObject.Properties[$Name]
  $modified = $false
  if ($null -eq $property -or $property.Value -ne $Value) {
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
  if ($confirmedValue -ne $Value) {
    throw "[$scriptName] Verification failed: $Path $Name = $confirmedValue; expected $Value."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $Path $Name = $confirmedValue"
}

$appPrivacyValues = @(
  "LetAppsAccessAccountInfo",
  "LetAppsAccessCalendar",
  "LetAppsAccessCallHistory",
  "LetAppsAccessContacts",
  "LetAppsAccessEmail",
  "LetAppsAccessLocation",
  "LetAppsAccessMessaging",
  "LetAppsAccessMotion",
  "LetAppsAccessNotifications",
  "LetAppsAccessRadios",
  "LetAppsAccessTrustedDevices",
  "LetAppsSyncWithDevices",
  "LetAppsAccessMicrophone",
  "LetAppsAccessCamera"
)

foreach ($name in $appPrivacyValues) {
  Set-ConfirmedRegistryValue -Path $appPrivacyPath -Name $name -Value 2 -Type DWORD
}

Set-ConfirmedRegistryValue -Path $smartGlassPath -Name "UserAuthPolicy" -Value 2 -Type DWORD

# The legacy per-app DeviceAccess key is ignored on Windows 10 1903 (build 18362) and later.
if ([Environment]::OSVersion.Version.Build -lt 18362) {
  Set-ConfirmedRegistryValue -Path $deviceAccessPath -Name "Value" -Value "Deny" -Type String
}
else {
  Write-Host "[$scriptName] [skipped] Legacy DeviceAccess key is not used on this Windows build; contacts access is covered by LetAppsAccessContacts."
}
