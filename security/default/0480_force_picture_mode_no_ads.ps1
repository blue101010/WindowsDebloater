<#
.SYNOPSIS
Forces the Windows 11 lock screen into "Picture" mode and removes lock-screen ads, tips
and fun facts.

.DESCRIPTION
Disables Windows Spotlight rotation, the slideshow, and the "fun facts, tips, tricks"
overlay on the lock screen so a static picture is shown without promotional content.
Sets the following current-user registry values:

  HKCU:\Control Panel\Desktop
    LockScreenAutoLockActive           (REG_SZ "0")  - Slideshow auto-lock behavior
  HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager
    RotatingLockScreenEnabled          (DWORD 0)     - Windows Spotlight rotating images
    RotatingLockScreenOverlayEnabled   (DWORD 0)     - Spotlight overlay (tips/ads)
    SubscribedContent-338387Enabled    (DWORD 0)     - "Get fun facts, tips, tricks and more on your lock screen"
  HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen
    SlideshowEnabled                   (DWORD 0)     - Lock-screen slideshow
    LockScreenWidgetsEnabled           (DWORD 0)     - "Lock screen status" = None (no "Weather and more")
    AutoSelectWidgetsOnLockScreen      (DWORD 0)     - Stop Windows re-selecting "Weather and more"
  HKLM:\SOFTWARE\Policies\Microsoft\Dsh (only when elevated)
    DisableWidgetsOnLockScreen         (DWORD 1)     - Policy: block widgets on the lock screen

.NOTES
- HKCU values need no administrator rights; the HKLM policy is applied only when elevated.
- Sign out or lock (Win+L) to see the change; pick an image in
  Settings > Personalization > Lock screen if needed.
- Creates keys and values if missing, then reads each value back to confirm it.
- To undo, set the DWORD values to 1 (or delete them) and LockScreenAutoLockActive to "1";
  delete HKLM:\SOFTWARE\Policies\Microsoft\Dsh\DisableWidgetsOnLockScreen.
- Overlaps: 0469 (other ContentDeliveryManager values).
#>

$scriptName = "0480_force_picture_mode_no_ads"
$settings = @(
  @{ Path = "HKCU:\Control Panel\Desktop"; Name = "LockScreenAutoLockActive"; Value = "0"; Type = "String" },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RotatingLockScreenEnabled"; Value = 0; Type = "DWord" },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RotatingLockScreenOverlayEnabled"; Value = 0; Type = "DWord" },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338387Enabled"; Value = 0; Type = "DWord" },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen"; Name = "SlideshowEnabled"; Value = 0; Type = "DWord" },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen"; Name = "LockScreenWidgetsEnabled"; Value = 0; Type = "DWord" },
  @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen"; Name = "AutoSelectWidgetsOnLockScreen"; Value = 0; Type = "DWord" }
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
  $settings += @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"; Name = "DisableWidgetsOnLockScreen"; Value = 1; Type = "DWord" }
} else {
  Write-Host "[$scriptName] Not elevated: skipping HKLM policy Dsh\DisableWidgetsOnLockScreen (run as admin to enforce)."
}

foreach ($setting in $settings) {
  $path = $setting.Path
  $name = $setting.Name
  $targetValue = $setting.Value

  if (-not (Test-Path -Path $path -ErrorAction Stop)) {
    New-Item -Path $path -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $path"
  }

  $property = (Get-ItemProperty -Path $path -ErrorAction Stop).PSObject.Properties[$name]
  $modified = $false
  if ($null -eq $property -or "$($property.Value)" -ne "$targetValue") {
    Set-ItemProperty -Path $path -Name $name -Value $targetValue -Type $setting.Type -Force -ErrorAction Stop
    $modified = $true
  }

  $confirmedValue = Get-ItemPropertyValue -Path $path -Name $name -ErrorAction Stop
  if ("$confirmedValue" -ne "$targetValue") {
    throw "[$scriptName] Verification failed: $path $name = $confirmedValue; expected $targetValue."
  }

  $status = if ($modified) { "[changed]" } else { "[no change]" }
  Write-Host "[$scriptName] [confirmed] $status $path $name = $confirmedValue ($($setting.Type))"
}
