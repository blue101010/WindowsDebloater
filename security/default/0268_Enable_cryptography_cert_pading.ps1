# Get CVE_2013_3900_mitigation_status

<#
.SYNOPSIS
    Creates two registry entries to mitigate WinVerifyTrust Signature Validation Vulnerability CVE-2013-3900
.DESCRIPTION
    This script creates the two necessary registry entries to mitigate WinVerifyTrust Signature Validation Vulnerability CVE-2013-3900 
    Creates missing keys, sets EnableCertPaddingCheck to String "1", and verifies
    each applicable registry view. Run as Administrator in 64-bit PowerShell on
    64-bit Windows. Registry access and verification failures stop execution.
    Reports registry configuration, not a live WinVerifyTrust test.
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900    
  #https://github.com/tpn/winddk-8.1/blob/master/Include/um/WinTrust.h
#https://www-bleepingcomputer-com.cdn.ampproject.org/c/s/www.bleepingcomputer.com/news/microsoft/10-year-old-windows-bug-with-opt-in-fix-exploited-in-3cx-attack/amp/
#https://github.com/Mr-Un1k0d3r/ATP-PowerShell-Scripts/blob/main/211ef051-ecf9-4b99-9eed-76e45a831a19.ps1
#>



if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
  throw "[0268_Enable_cryptography_cert_pading] Run in 64-bit PowerShell to configure both registry views."
}

$RegentryName = "EnableCertPaddingCheck"
$registryPaths = @("HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config")
if ([Environment]::Is64BitOperatingSystem) {
  $registryPaths += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
}

foreach ($path in $registryPaths) {
  $modified = $false
  if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
    Write-Output "[0268_Enable_cryptography_cert_pading] Registry key missing: $path. Creating it..."
    New-Item -Path $path -Force -ErrorAction Stop | Out-Null
  }
  $properties = Get-ItemProperty -Path $path -ErrorAction Stop
  $property = $properties.PSObject.Properties[$RegentryName]
  if ($null -eq $property -or $property.Value -ne "1") {
    Set-ItemProperty -Path $path -Name $RegentryName -Value "1" -Type String -Force -ErrorAction Stop
    $modified = $true
  }
  $confirmedValue = Get-ItemPropertyValue -Path $path -Name $RegentryName -ErrorAction Stop
  if ($confirmedValue -ne "1") {
    throw "[0268_Enable_cryptography_cert_pading] Verification failed: $path $RegentryName = '$confirmedValue'; expected 1."
  }
  $view = if ($path -like "*\Wow6432Node\*" -or -not [Environment]::Is64BitOperatingSystem) { "32-bit" } else { "64-bit" }
  $status = if ($modified) { "changed" } else { "no change" }
  Write-Output "[0268_Enable_cryptography_cert_pading] [confirmed] [$status] $view : $path $RegentryName = $confirmedValue"
}
Write-Output "[0268_Enable_cryptography_cert_pading] CVE-2013-3900 mitigation registry configuration confirmed in all applicable views."

