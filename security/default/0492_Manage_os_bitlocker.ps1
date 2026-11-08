#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('On', 'Off', 'Status')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$Drive = 'C:'

try {
    if (-not $PSBoundParameters.ContainsKey('Action')) {
        do {
            Write-Host 'Manage BitLocker on C:'
            Write-Host '  1. Turn off (decrypt) [default]'
            Write-Host '  2. Turn on'
            Write-Host '  3. Show status'
            Write-Host '  0. Cancel'
            $choice = Read-Host 'Choose an option'

            switch ($choice) {
                { $_ -eq '' -or $_ -eq '1' } { $Action = 'Off' }
                '2' { $Action = 'On' }
                '3' { $Action = 'Status' }
                '0' {
                    Write-Host 'Cancelled.'
                    return
                }
                default { Write-Host 'Invalid choice. Enter 1, 2, 3, or 0.' }
            }
        } while (-not $Action)
    }

    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        throw 'BitLocker PowerShell cmdlets are unavailable on this Windows installation.'
    }

    $volume = Get-BitLockerVolume -MountPoint $Drive

    switch ($Action) {
        'Off' {
            if ($volume.VolumeStatus -eq 'FullyDecrypted') {
                Write-Host "$Drive is already fully decrypted."
            }
            elseif ($volume.VolumeStatus -eq 'DecryptionInProgress') {
                Write-Host 'Decryption is already running.'
            }
            else {
                $answer = Read-Host "Decrypt $Drive and remove BitLocker protection? Type YES"
                if ($answer -ne 'YES') {
                    Write-Host 'Cancelled.'
                    return
                }

                Disable-BitLocker -MountPoint $Drive | Out-Null
                Write-Host 'Decryption requested. Check progress with -Action Status.'
            }
        }

        'On' {
            if ($volume.VolumeStatus -in @(
                'DecryptionInProgress', 'DecryptionPaused'
            )) {
                throw 'Let decryption finish before enabling BitLocker again.'
            }

            if ($volume.ProtectionStatus -eq 'On') {
                Write-Host 'BitLocker protection is already on.'
            }
            else {
                $freshEncryption = $volume.VolumeStatus -eq 'FullyDecrypted'

                if ($freshEncryption) {
                    $tpm = Get-Tpm
                    if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
                        throw 'This script requires a present, ready TPM to enable encryption.'
                    }
                }

                $recovery = @(
                    $volume.KeyProtector |
                        Where-Object KeyProtectorType -eq 'RecoveryPassword'
                )

                if ($recovery.Count -eq 0) {
                    Add-BitLockerKeyProtector -MountPoint $Drive `
                        -RecoveryPasswordProtector | Out-Null

                    $volume = Get-BitLockerVolume -MountPoint $Drive
                    $recovery = @(
                        $volume.KeyProtector |
                            Where-Object KeyProtectorType -eq 'RecoveryPassword'
                    )
                }

                Write-Warning 'Keep these recovery details private.'
                $recovery |
                    Format-List KeyProtectorId, RecoveryPassword |
                    Out-Host

                $answer = Read-Host 'Saved the recovery password somewhere safe outside this PC? Type YES'
                if ($answer -ne 'YES') {
                    Write-Host 'Cancelled; protection was not enabled.'
                    return
                }

                if ($freshEncryption) {
                    Enable-BitLocker -MountPoint $Drive `
                        -TpmProtector | Out-Null

                    Write-Host 'BitLocker enablement requested. Restart if prompted.'
                }
                else {
                    Resume-BitLocker -MountPoint $Drive | Out-Null
                    Write-Host 'BitLocker protection resumed.'
                }
            }
        }

        'Status' {
            # Status is displayed below without changing anything.
        }
    }

    Get-BitLockerVolume -MountPoint $Drive |
        Select-Object MountPoint, VolumeStatus,
            EncryptionPercentage, ProtectionStatus, EncryptionMethod |
        Format-List
}
catch {
    Write-Error $_
}