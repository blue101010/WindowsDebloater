#Requires -RunAsAdministrator

$scriptName = '0493_disable_windows_disableStatupSound'

# --- 1. Disable the Windows startup sound (machine-wide) ---
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation'
$propertyName = 'DisableStartupSound'
$targetValue = 1
$currentValue = $null

Write-Host "[$scriptName] Checking $propertyName..."
if (Test-Path -Path $path -ErrorAction Stop) {
    $properties = Get-ItemProperty -Path $path -ErrorAction Stop
    $property = $properties.PSObject.Properties[$propertyName]
    if ($null -ne $property) {
        $currentValue = $property.Value
    }
}

if ($null -eq $currentValue) {
    Write-Host "[$scriptName] [Status] $propertyName is missing."
}
else {
    Write-Host "[$scriptName] [Status] $propertyName = $currentValue"
}

if ($currentValue -ne $targetValue) {
    Write-Host "[$scriptName] [Updating] Setting $propertyName to $targetValue."
    New-Item -Path $path -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $path `
        -Name $propertyName `
        -PropertyType DWord `
        -Value $targetValue `
        -Force `
        -ErrorAction Stop | Out-Null
}
else {
    Write-Host "[$scriptName] [Already configured] No change needed."
}

$verifiedValue = Get-ItemPropertyValue -Path $path -Name $propertyName -ErrorAction Stop
if ($verifiedValue -ne $targetValue) {
    throw "[$scriptName] Verification failed: $propertyName is $verifiedValue, expected $targetValue."
}

Write-Host "[$scriptName] [Confirmed] $propertyName = $verifiedValue."

# --- 2. Force the "No Sounds" scheme ---
# HKCU = current user; HKU\.DEFAULT = logon screen / system context.
$appEventRoots = @(
    'HKCU:\AppEvents',
    'Registry::HKEY_USERS\.DEFAULT\AppEvents'
)

function Get-DefaultRegistryValue {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    $key = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    return $key.GetValue('', $null, 'DoNotExpandEnvironmentNames')
}

foreach ($root in $appEventRoots) {
    $schemesPath = Join-Path $root 'Schemes'
    $appsPath = Join-Path $schemesPath 'Apps'

    if (-not (Test-Path -LiteralPath $appsPath)) {
        Write-Host "[$scriptName] [Skipped] $appsPath not found."
        continue
    }

    Write-Host "[$scriptName] Checking sound scheme in $schemesPath..."
    $currentScheme = Get-DefaultRegistryValue -LiteralPath $schemesPath
    Write-Host "[$scriptName] [Status] Active scheme = '$currentScheme'"
    if ($currentScheme -ne '.None') {
        Write-Host "[$scriptName] [Updating] Selecting 'No Sounds' (.None) scheme."
        Set-ItemProperty -LiteralPath $schemesPath -Name '(Default)' -Value '.None' -ErrorAction Stop
    }

    # Silence every event sound currently assigned (.Current), keeping .Default intact.
    $currentKeys = @(Get-ChildItem -LiteralPath $appsPath -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -eq '.Current' })

    $silenced = 0
    foreach ($key in $currentKeys) {
        $value = $key.GetValue('', $null, 'DoNotExpandEnvironmentNames')
        if (-not [string]::IsNullOrEmpty($value)) {
            Set-ItemProperty -LiteralPath $key.PSPath -Name '(Default)' -Value '' -ErrorAction Stop
            $silenced++
        }
    }

    if ($silenced -gt 0) {
        Write-Host "[$scriptName] [Updating] Silenced $silenced event sound(s) in $appsPath."
    }
    else {
        Write-Host "[$scriptName] [Already configured] All $($currentKeys.Count) event sound(s) already silent."
    }

    # Verification
    $verifiedScheme = Get-DefaultRegistryValue -LiteralPath $schemesPath
    if ($verifiedScheme -ne '.None') {
        throw "[$scriptName] Verification failed: scheme in $schemesPath is '$verifiedScheme', expected '.None'."
    }

    $remaining = @($currentKeys | Where-Object {
            -not [string]::IsNullOrEmpty((Get-DefaultRegistryValue -LiteralPath $_.PSPath))
        })
    if ($remaining.Count -gt 0) {
        $list = ($remaining | ForEach-Object { $_.Name }) -join "`n  "
        throw "[$scriptName] Verification failed: $($remaining.Count) event sound(s) still assigned:`n  $list"
    }

    Write-Host "[$scriptName] [Confirmed] 'No Sounds' scheme active in $schemesPath ($($currentKeys.Count) events silent)."
}
