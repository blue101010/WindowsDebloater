#Requires -Version 5.1

<#
.SYNOPSIS
	Lists common persistence-related registry locations and highlights potentially malicious script entries.
.DESCRIPTION
	This script reads specific HKCU/HKLM autorun and Active Setup locations,
	prints discovered entries, and flags values that look like script-based persistence.
	It does not modify the system.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section {
	param(
		[Parameter(Mandatory=$true)]
		[string]$Title
	)

	Write-Host "" 
	Write-Host "============================================================" -ForegroundColor Cyan
	Write-Host $Title -ForegroundColor Cyan
	Write-Host "============================================================" -ForegroundColor Cyan
}

function Test-SuspiciousPersistenceData {
	param(
		[AllowNull()]
		[AllowEmptyString()]
		[string]$Data
	)

	if ([string]::IsNullOrWhiteSpace($Data)) {
		return $false
	}

	$patterns = @(
		'\.ps1(\s|$)',
		'\.vbs(\s|$)',
		'\.js(\s|$)',
		'\.jse(\s|$)',
		'\.wsf(\s|$)',
		'\.hta(\s|$)',
		'powershell(\.exe)?\s',
		'wscript(\.exe)?\s',
		'cscript(\.exe)?\s',
		'mshta(\.exe)?\s',
		'rundll32(\.exe)?\s',
		'regsvr32(\.exe)?\s',
		'https?://',
		'%temp%|\\temp\\|appdata\\local\\temp'
	)

	foreach ($pattern in $patterns) {
		if ($Data -match $pattern) {
			return $true
		}
	}

	return $false
}

function Get-RegistryPathEntries {
	param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[string[]]$OnlyValueNames
	)

	if (-not (Test-Path -Path $Path)) {
		Write-Host "[NOT FOUND] $Path" -ForegroundColor Yellow
		return @()
	}

	$item = Get-ItemProperty -Path $Path -ErrorAction Stop
	$entries = @()

	if ($OnlyValueNames -and $OnlyValueNames.Count -gt 0) {
		foreach ($valueName in $OnlyValueNames) {
			$value = $null
			try {
				$value = $item.$valueName
			} catch {
				$value = $null
			}

			if ($null -ne $value) {
				$entries += [PSCustomObject]@{
					Path = $Path
					Name = $valueName
					Data = [string]$value
					Suspicious = (Test-SuspiciousPersistenceData -Data ([string]$value)
					)
				}
			}
		}

		return $entries
	}

	foreach ($property in $item.PSObject.Properties) {
		if ($property.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
			continue
		}

		$entries += [PSCustomObject]@{
			Path = $Path
			Name = $property.Name
			Data = [string]$property.Value
			Suspicious = (Test-SuspiciousPersistenceData -Data ([string]$property.Value)
			)
		}
	}

	return $entries
}

function Get-ActiveSetupEntries {
	param(
		[Parameter(Mandatory=$true)]
		[string]$Path
	)

	if (-not (Test-Path -Path $Path)) {
		Write-Host "[NOT FOUND] $Path" -ForegroundColor Yellow
		return @()
	}

	$entries = @()
	$subKeys = Get-ChildItem -Path $Path -ErrorAction Stop

	foreach ($subKey in $subKeys) {
		$subPath = $subKey.PSPath
		$sub = Get-ItemProperty -Path $subPath -ErrorAction SilentlyContinue
		if ($null -eq $sub) {
			continue
		}

		$stubPath = $null
		try {
			$stubPath = [string]$sub.StubPath
		} catch {
			$stubPath = $null
		}

		if (-not [string]::IsNullOrWhiteSpace($stubPath)) {
			$entries += [PSCustomObject]@{
				Path = $subKey.Name
				Name = 'StubPath'
				Data = $stubPath
				Suspicious = (Test-SuspiciousPersistenceData -Data $stubPath)
			}
		}
	}

	return $entries
}

Write-Section -Title "Registry Persistence Check"
Write-Host "Goal: identify potential malicious scripts stored for persistence." -ForegroundColor Gray

$allFindings = @()

# Requested key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
$allFindings += Get-RegistryPathEntries -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# Requested key: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
$allFindings += Get-RegistryPathEntries -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'

# Requested key: HKCU\Software\Microsoft\Active Setup\Installed Components
$allFindings += Get-ActiveSetupEntries -Path 'HKCU:\Software\Microsoft\Active Setup\Installed Components'

# Requested key: HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
$allFindings += Get-RegistryPathEntries -Path 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'

# Requested value: HKCU\Environment\UserInitMprLogonScript
$allFindings += Get-RegistryPathEntries -Path 'HKCU:\Environment' -OnlyValueNames @('UserInitMprLogonScript')

Write-Section -Title "Discovered Entries"
if (-not $allFindings -or $allFindings.Count -eq 0) {
	Write-Host "No matching entries found in the requested locations." -ForegroundColor Yellow
} else {
	foreach ($entry in $allFindings) {
		$color = if ($entry.Suspicious) { 'Red' } else { 'Green' }
		$tag = if ($entry.Suspicious) { '[SUSPICIOUS]' } else { '[OK]' }

		Write-Host "$tag Path : $($entry.Path)" -ForegroundColor $color
		Write-Host "      Name : $($entry.Name)" -ForegroundColor Gray
		Write-Host "      Data : $($entry.Data)" -ForegroundColor Gray
		Write-Host ""
	}
}

$suspiciousFindings = @($allFindings | Where-Object { $_.Suspicious })

Write-Section -Title "Summary"
Write-Host "Total entries evaluated : $($allFindings.Count)" -ForegroundColor Gray
Write-Host "Suspicious entries      : $($suspiciousFindings.Count)" -ForegroundColor $(if ($suspiciousFindings.Count -gt 0) { 'Red' } else { 'Green' })

if ($suspiciousFindings.Count -gt 0) {
	Write-Host "Review suspicious items immediately and validate publishers/paths." -ForegroundColor Yellow
}

