<#
.SYNOPSIS
	Check and manage Dell Trusted Device and Windows telemetry registry settings.

.DESCRIPTION
	This script checks the Dell Trusted Device telemetry opt-in and the Windows
	DataCollection AllowTelemetry policy registry values. It can report the
	current state, or enable/disable telemetry by writing the appropriate
	DWORD values under HKLM.

.PARAMETER Action
	One of: 'disable' (default), 'enable', or 'check'.
	- 'disable' will set Dell TelemetryOptin and Windows AllowTelemetry to 0.
	- 'enable' will set those values to 1.
	- 'check' will only report current values and not modify the registry.

.EXAMPLE
	.\0446_Disable_check_Dell_trusted_device_telemetry.ps1
	(Defaults to disabling telemetry.)

.EXAMPLE
	.\0446_Disable_check_Dell_trusted_device_telemetry.ps1 -Action check
	(Only display current registry values.)

.NOTES
	Requires elevated privileges to write to HKLM. Use with caution.

References:
https://www.dell.com/support/kbdoc/en-ca/000195538/how-to-disable-telemetry-data-collection-in-dell-trusted-device-post-install
#>

param(
	[Parameter(Position=0)]
	[ValidateSet('disable','enable','check')]
	[string]$Action = 'disable'
)

function Test-IsAdministrator {
	$current = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal($current)
	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


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
			New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
		} catch {
			Write-Output "ERROR: Failed to create registry path $Path : $_"
			return $false
		}
	}

	try {
		$existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
		# If we got here, property exists
		Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
	} catch [System.Management.Automation.ItemNotFoundException] {
		try {
			New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force -ErrorAction Stop | Out-Null
		} catch {
			Write-Output "ERROR: Failed to create $Path\$Name = $Value : $_"
			return $false
		}
	} catch {
		Write-Output "ERROR: Failed to set $Path\$Name to $Value : $_"
		return $false
	}

	return $true
}

# Paths and value names
$dellPath = 'HKLM:\SOFTWARE\Dell\TrustedDevice'
$dellName = 'TelemetryOptin'

$winPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$winName = 'AllowTelemetry'

Write-Output "Action: $Action"
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

if ($Action -eq 'check') {
	Write-Output "Check-only mode: no changes will be made."
	Write-Output "Done."
	return
}

$desired = if ($Action -eq 'disable') { 0 } else { 1 }

Write-Output "Determining required changes for action '$Action' (desired = $desired)..."

$dellNeeds = $false
if ($dellVal -eq $null) { $dellNeeds = $true } elseif ($dellVal -ne $desired) { $dellNeeds = $true }

$winNeeds = $false
if ($winVal -eq $null) { $winNeeds = $true } elseif ($winVal -ne $desired) { $winNeeds = $true }

if (-not $dellNeeds -and -not $winNeeds) {
	Write-Output "No changes required: Dell and Windows telemetry values already set to $desired."
	Write-Output "Done."
	return
}

Write-Output "Changes required: DellNeeded=$dellNeeds, WindowsNeeded=$winNeeds"

if (-not (Test-IsAdministrator)) {
	Write-Error "Registry changes are required but the script is not running elevated. Re-run as Administrator to apply changes."
	exit 1
}

Write-Output "Applying required changes..."

$dellOk = $true
$winOk = $true

if ($dellNeeds) {
	$dellOk = Ensure-RegistryDword -Path $dellPath -Name $dellName -Value $desired
	if ($dellOk) { Write-Output "Set $dellPath\$dellName = $desired" }
}

if ($winNeeds) {
	$winOk = Ensure-RegistryDword -Path $winPath -Name $winName -Value $desired
	if ($winOk) { Write-Output "Set $winPath\$winName = $desired" }
}

if ($dellOk -and $winOk) {
	Write-Output "Success: requested telemetry registry values set to $desired."
} elseif ($dellOk -or $winOk) {
	Write-Output "Partial success: some values updated. Check errors above for details."
} else {
	Write-Output "Failed: could not update any registry values. Ensure the script is run elevated and you have permission."
}

Write-Output "Done."

