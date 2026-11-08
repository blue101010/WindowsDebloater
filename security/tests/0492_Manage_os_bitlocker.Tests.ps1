$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot '..\default\0492_Manage_os_bitlocker.ps1'
$source = [IO.File]::ReadAllText((Resolve-Path $file))
if (-not $source.Contains('#Requires -RunAsAdministrator')) {
    throw 'The administrator requirement is missing.'
}
$block = [scriptblock]::Create($source.Replace('#Requires -RunAsAdministrator', ''))

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Read-Host {
    param($Prompt)
    if ($script:answers.Count -eq 0) { throw "Unexpected prompt: $Prompt" }
    $script:prompts += $Prompt
    $answer = $script:answers[0]
    $script:answers = @($script:answers | Select-Object -Skip 1)
    return $answer
}

function Get-BitLockerVolume {
    param($MountPoint)
    Assert-Test ($MountPoint -eq 'C:') 'Unexpected mount point.'
    $script:volumeReads++
    [pscustomobject]@{
        MountPoint = 'C:'
        VolumeStatus = $script:volumeStatus
        ProtectionStatus = $script:protectionStatus
        KeyProtector = @([pscustomobject]@{
            KeyProtectorType = 'RecoveryPassword'
            KeyProtectorId = 'test'
            RecoveryPassword = 'test'
        })
    }
}

function Disable-BitLocker {
    param($MountPoint)
    Assert-Test ($MountPoint -eq 'C:') 'Unexpected disable mount point.'
    $script:disabled++
}

function Get-Tpm { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
function Add-BitLockerKeyProtector { throw 'Unexpected recovery protector change.' }
function Resume-BitLocker { throw 'Unexpected protection resume.' }
function Enable-BitLocker {
    param($MountPoint, [switch]$TpmProtector)
    Assert-Test ($MountPoint -eq 'C:' -and $TpmProtector) 'Unexpected enable arguments.'
    $script:enabled++
}

function Reset-Test {
    param([string[]]$Answers, [string]$VolumeStatus = 'FullyEncrypted', [string]$ProtectionStatus = 'On')
    $script:answers = @($Answers)
    $script:prompts = @()
    $script:volumeReads = 0
    $script:disabled = 0
    $script:enabled = 0
    $script:volumeStatus = $VolumeStatus
    $script:protectionStatus = $ProtectionStatus
}

Reset-Test -Answers @('', 'YES')
& $block 6>$null | Out-Null
Assert-Test ($script:disabled -eq 1 -and $script:enabled -eq 0) 'Default choice did not disable BitLocker.'
Assert-Test ($script:prompts.Count -eq 2) 'Default choice skipped the decryption confirmation.'

Reset-Test -Answers @('1', 'YES')
& $block 6>$null | Out-Null
Assert-Test ($script:disabled -eq 1) 'Off choice did not disable BitLocker.'

Reset-Test -Answers @('1', 'NO')
& $block 6>$null | Out-Null
Assert-Test ($script:disabled -eq 0) 'Declined decryption still disabled BitLocker.'

Reset-Test -Answers @('2', 'YES') -VolumeStatus 'FullyDecrypted' -ProtectionStatus 'Off'
& $block 6>$null 3>$null | Out-Null
Assert-Test ($script:enabled -eq 1 -and $script:disabled -eq 0) 'On choice did not enable BitLocker.'

Reset-Test -Answers @('2', 'NO') -VolumeStatus 'FullyDecrypted' -ProtectionStatus 'Off'
& $block 6>$null 3>$null | Out-Null
Assert-Test ($script:enabled -eq 0) 'Declined recovery confirmation still enabled BitLocker.'

Reset-Test -Answers @('invalid', '3')
& $block 6>$null | Out-Null
Assert-Test ($script:prompts.Count -eq 2 -and $script:volumeReads -eq 2 -and $script:disabled -eq 0) 'Invalid choice was not retried before status.'

Reset-Test -Answers @('0')
& $block 6>$null | Out-Null
Assert-Test ($script:volumeReads -eq 0) 'Cancel accessed BitLocker.'

Reset-Test -Answers @()
& $block -Action Status 6>$null | Out-Null
Assert-Test ($script:prompts.Count -eq 0 -and $script:volumeReads -eq 2) 'Explicit status unexpectedly showed the menu.'

Reset-Test -Answers @('YES')
& $block -Action Off 6>$null | Out-Null
Assert-Test ($script:prompts.Count -eq 1 -and $script:disabled -eq 1) 'Explicit off did not preserve confirmation and bypass the menu.'

Reset-Test -Answers @('YES') -VolumeStatus 'FullyDecrypted' -ProtectionStatus 'Off'
& $block -Action On 6>$null 3>$null | Out-Null
Assert-Test ($script:prompts.Count -eq 1 -and $script:enabled -eq 1) 'Explicit on did not preserve confirmation and bypass the menu.'

Write-Host '[PASS] BitLocker menu, confirmations, cancellation, and explicit actions.'
