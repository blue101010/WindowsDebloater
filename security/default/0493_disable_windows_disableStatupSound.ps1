#Requires -RunAsAdministrator

$scriptName = '0493_disable_windows_disableStatupSound'
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