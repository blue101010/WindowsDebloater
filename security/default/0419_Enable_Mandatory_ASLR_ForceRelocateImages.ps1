<#!
.SYNOPSIS
	View or enable Mandatory ASLR (ForceRelocateImages) via menu or batch mode.

.DESCRIPTION
	Provides two actions:
	  • Get: display the current system exploit mitigation configuration.
	  • Set: enable ForceRelocateImages (Mandatory ASLR) and then show the new state.
	When run without parameters it opens an interactive menu. Using -Action get or -Action set
	enables automation. Selecting Set from a non-elevated context triggers a UAC prompt to
	re-run the script with administrative rights before applying the mitigation.

.NOTES
	Policy-enforced exploit protection or virtualization-based security can block
	Set-ProcessMitigation calls and return STATUS_ACCESS_DENIED (0xC0000022).
	#>

param(
	[Alias('Mode')]
	[ValidateSet('menu','get','set')]
	[string]$Action = 'menu',

	[switch]$Help,

	[switch]$SkipConfirm
)

function Show-Usage {
	Write-Host "Usage:" -ForegroundColor Cyan
	Write-Host "  pwsh ./0419_Enable_Mandatory_ASLR_ForceRelocateImages.ps1 -Action menu" -ForegroundColor Gray
	Write-Host "  pwsh ./0419_Enable_Mandatory_ASLR_ForceRelocateImages.ps1 -Action get" -ForegroundColor Gray
	Write-Host "  pwsh ./0419_Enable_Mandatory_ASLR_ForceRelocateImages.ps1 -Action set" -ForegroundColor Gray
	Write-Host "Menu options:" -ForegroundColor Gray
	Write-Host "  1) Show current system mitigations" -ForegroundColor Gray
	Write-Host "  2) Enable ForceRelocateImages (Mandatory ASLR)" -ForegroundColor Gray
}


function Show-ForceRelocateSummary {
	param([string]$Prefix)
	try {
		$state = (Get-ProcessMitigation -System).ASLR.ForceRelocateImages
		$message = "$Prefix Mandatory ASLR (ForceRelocateImages): $state"
		$color = $state -eq 'ON' ? 'Green' : 'Yellow'
		Write-Host $message -ForegroundColor $color
	}
	catch {
		Write-Warning "$Prefix Mandatory ASLR summary unavailable: $($_.Exception.Message)"
	}
}

function Show-ForceRelocateDetails {
	try {
		$systemString = Get-ProcessMitigation -System | Out-String
		$match = $systemString | Select-String -Pattern 'ForceRelocateImages\s*:\s*ON'
		if ($match) {
			Write-Host "  System string indicates ForceRelocateImages : ON" -ForegroundColor Green
		}
		else {
			Write-Host "  System string indicates ForceRelocateImages : OFF" -ForegroundColor Yellow
		}

		$rawState = (Get-ProcessMitigation -System).ASLR.ForceRelocateImages
		Write-Host ("  Raw state (Get-ProcessMitigation -System).ASLR.ForceRelocateImages : {0}" -f $rawState) -ForegroundColor Gray

		try {
			$processState = (Get-ProcessMitigation -Name notepad.exe -ErrorAction Stop).ASLR.ForceRelocateImages
			Write-Host ("  notepad.exe ForceRelocateImages : {0}" -f $processState) -ForegroundColor Gray
		}
		catch {
			Write-Host "  notepad.exe ForceRelocateImages : (process not available)" -ForegroundColor DarkGray
		}
	}
	catch {
		Write-Warning "Unable to display ForceRelocateImages details: $($_.Exception.Message)"
	}
}

function Test-IsAdministrator {
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = [Security.Principal.WindowsPrincipal]::new($currentUser)
	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-GetMitigations {
	Write-Host "Current system exploit mitigation settings:" -ForegroundColor Cyan
	Get-ProcessMitigation -System
	Show-ForceRelocateSummary -Prefix 'Current'
	Show-ForceRelocateDetails
}

function Invoke-SetForceRelocateImages {
		try {
			$currentState = (Get-ProcessMitigation -System).ASLR.ForceRelocateImages
		}
		catch {
			Write-Warning "Unable to read current ForceRelocateImages state: $($_.Exception.Message)"
			$currentState = 'Unknown'
		}
		if (-not $SkipConfirm) {
			if ($currentState -eq 'ON') {
				Write-Host "ForceRelocateImages is already ON. Reapply anyway?" -ForegroundColor Yellow
			}
			else {
				Write-Host "ForceRelocateImages is currently OFF. Enabling improves compatibility but may impact legacy binaries." -ForegroundColor Yellow
			}

			do {
				$confirmation = Read-Host "Proceed with enabling ForceRelocateImages? (Y/N)"
			} while ($confirmation -notmatch '^[YyNn]$')

			if ($confirmation -match '^[Nn]$') {
				Write-Host "Operation cancelled by user. Returning to menu." -ForegroundColor Yellow
				return
			}
		} else {
			Write-Host "Confirmation skipped (already approved prior to elevation)." -ForegroundColor DarkGray
		}

		if (-not (Test-IsAdministrator)) {
			Write-Warning "ForceRelocateImages requires administrative privileges. Requesting elevation..."
			$exe = (Get-Process -Id $PID).Path
			$argList = @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',"`"$PSCommandPath`"",'-Action','set','-SkipConfirm')
			try {
				$proc = Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs -Wait -PassThru
			if ($proc.ExitCode -ne 0) {
				Write-Warning "Elevated process exited with code $($proc.ExitCode). Review the elevated window for errors."
			}
		}
		catch {
			Write-Error "UAC elevation was rejected or failed: $($_.Exception.Message)"
		}
		return
	}

	Write-Host "Enabling ForceRelocateImages (Mandatory ASLR)..." -ForegroundColor Cyan
	try {
		Set-ProcessMitigation -System -Enable ForceRelocateImages -ErrorAction Stop
		Write-Host "Updated system exploit mitigation settings:" -ForegroundColor Cyan
		Get-ProcessMitigation -System
		Show-ForceRelocateSummary -Prefix 'Updated'
		Show-ForceRelocateDetails
	}
	catch {
		Write-Error "Failed to enable ForceRelocateImages: $($_.Exception.Message)"
	}
}

function Show-MainMenu {
	do {
		Write-Host "================ Mandatory ASLR Helper ================" -ForegroundColor Cyan
		Write-Host "1) Show current system mitigations"
		Write-Host "2) Enable ForceRelocateImages (Mandatory ASLR)"
		Write-Host "Q) Quit"
		$choice = Read-Host 'Select an option'
		switch ($choice.ToUpperInvariant()) {
			'1' { Invoke-GetMitigations }
			'2' { Invoke-SetForceRelocateImages }
			'Q' { Write-Host 'Exiting.' }
			Default { Write-Warning 'Invalid selection. Choose 1, 2, or Q.' }
		}
	} while ($choice.ToUpperInvariant() -ne 'Q')
}

if ($Help) {
	Show-Usage
	return
}

switch ($Action) {
	'get'  { Invoke-GetMitigations }
	'set'  { Invoke-SetForceRelocateImages }
	'menu' { Show-MainMenu }
}