<#
0446_Disable_check_Dell_trusted_device_telemetry.ps1

Checks Dell Trusted Device telemetry and Windows telemetry policy, reports status,
and disables Dell telemetry (and optionally Windows telemetry) by setting the
appropriate HKLM registry values to 0.

References:
https://www.dell.com/support/kbdoc/en-ca/000195538/how-to-disable-telemetry-data-collection-in-dell-trusted-device-post-install
#>

function Get-RegistryDword {
	param(
		[string]$Path,
		[string]$Name
	)
	try {
		$prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
		return [int]$prop.$Name
	} catch {
		return $null
	}
}

function Ensure-RegistryDword {
	param(
		[string]$Path,
		[string]$Name,
		[int]$Value
	)
	if (-not (Test-Path -Path $Path)) {
		try {
			New-Item -Path $Path -Force | Out-Null
		} catch {
			Write-Output "ERROR: Failed to create registry path $Path : $_"
			return $false
		}
	}

	try {
		$existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
		if ($null -ne $existing) {
			Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
		} else {
			New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
		}
		return $true
	} catch {
		Write-Output "ERROR: Failed to set $Path\$Name to $Value : $_"
		return $false
	}
}

# Paths and value names
$dellPath = 'HKLM:\SOFTWARE\Dell\TrustedDevice'
$dellName = 'TelemetryOptin'

$winPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$winName = 'AllowTelemetry'

Write-Output "Checking Dell Trusted Device telemetry and Windows telemetry policy..."

$dellVal = Get-RegistryDword -Path $dellPath -Name $dellName
$winVal  = Get-RegistryDword -Path $winPath -Name $winName

if ($dellVal -eq $null) {
	Write-Output "Dell: $dellPath\$dellName => Not present"
} else {
	Write-Output "Dell: $dellPath\$dellName => $dellVal (0=disabled,1=enabled)"
}

if ($winVal -eq $null) {
	Write-Output "Windows: $winPath\$winName => Not present"
} else {
	Write-Output "Windows: $winPath\$winName => $winVal (0=disabled)"
}

# Decide whether to act: if either indicates telemetry is enabled (non-zero)
$shouldDisable = $false
if ($dellVal -ne $null -and $dellVal -ne 0) { $shouldDisable = $true }
if ($winVal  -ne $null -and $winVal  -ne 0) { $shouldDisable = $true }

if ($shouldDisable) {
	Write-Output "One or more telemetry settings indicate telemetry is allowed. Applying disable actions..."

	$dellOk = Ensure-RegistryDword -Path $dellPath -Name $dellName -Value 0
	if ($dellOk) {
		Write-Output "Set $dellPath\$dellName = 0"
	}

	$winOk = Ensure-RegistryDword -Path $winPath -Name $winName -Value 0
	if ($winOk) {
		Write-Output "Set $winPath\$winName = 0"
	}

	if ($dellOk -and $winOk) {
		Write-Output "Success: Dell and Windows telemetry registry values set to 0."
	} elseif ($dellOk -or $winOk) {
		Write-Output "Partial success: some values updated. Check errors above for details."
	} else {
		Write-Output "Failed: could not update registry values. Ensure the script is run elevated."
	}
} else {
	Write-Output "No action required: telemetry registry values already set to disabled (0) or not present."
}

Write-Output "Done."

