<#
.SYNOPSIS
Disables the use of Windows Hello Biometrics by modifying the registry.

.DESCRIPTION
This script disables the use of Windows Hello Biometrics by modifying the registry value for the specified path and value name. It creates the registry path if missing, sets the value if needed, and reads it back to confirm.

.PARAMETER registryPath
The registry path where the value is located.

.PARAMETER registryValueName
The name of the registry value to be modified.

.PARAMETER disableValue
The value to set the registry value to in order to disable Windows Hello Biometrics.

.NOTES
- This script requires administrative privileges to modify the registry.
- Use with caution as modifying the registry can have unintended consequences.

.EXAMPLE
Disable-WindowsHelloBiometrics -registryPath "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -registryValueName "Enabled" -disableValue 0
#>
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics"
$registryValueName = "Enabled"
$disableValue = 0
$scriptName = "0048_Disable_Use_of_Windows_Hello_Biometrics"

if (-not (Test-Path -Path $registryPath -ErrorAction Stop)) {
    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
    Write-Host "[$scriptName] Created registry path: $registryPath"
}

$property = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).PSObject.Properties[$registryValueName]
$modified = $false
if ($null -eq $property -or $property.Value -ne $disableValue) {
    Set-ItemProperty -Path $registryPath -Name $registryValueName -Value $disableValue -Type DWORD -Force -ErrorAction Stop
    $modified = $true
}

$confirmedValue = Get-ItemPropertyValue -Path $registryPath -Name $registryValueName -ErrorAction Stop
if ($confirmedValue -ne $disableValue) {
    throw "[$scriptName] Verification failed: $registryPath $registryValueName = $confirmedValue; expected $disableValue."
}

$status = if ($modified) { "[changed]" } else { "[no change]" }
Write-Host "[$scriptName] [confirmed] $status $registryPath $registryValueName = $confirmedValue (disabled)"
