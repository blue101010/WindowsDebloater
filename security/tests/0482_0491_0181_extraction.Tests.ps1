$ErrorActionPreference = 'Stop'
$defaultDir = Join-Path $PSScriptRoot '..\default'
$testRoot = 'Software\WindowsDebloater-Test-' + [guid]::NewGuid()
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
$script:testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = '22000' }

function Get-CimInstance {
  param($ClassName, $ErrorAction)
  return $script:testOS
}

function Assert-Test {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Get-IsolatedScript {
  param([string]$File, [string]$Prefix, [hashtable]$Replacements = @{})
  $source = [IO.File]::ReadAllText((Join-Path $defaultDir $File))
  foreach ($token in @('$hive = [Microsoft.Win32.RegistryHive]::LocalMachine', "`$basePath = ''")) {
    Assert-Test ($source.Contains($token)) "${File}: missing production token '$token'."
  }
  $source = $source.Replace('$hive = [Microsoft.Win32.RegistryHive]::LocalMachine', '$hive = [Microsoft.Win32.RegistryHive]::CurrentUser')
  $source = $source.Replace("`$basePath = ''", "`$basePath = '$Prefix\'")
  foreach ($key in $Replacements.Keys) {
    Assert-Test ($source.Contains($key)) "${File}: missing token '$key'."
    $source = $source.Replace($key, $Replacements[$key])
  }
  return [scriptblock]::Create($source)
}

function Assert-Values {
  param([string]$File, [string]$Prefix, [object[]]$Expected)
  foreach ($e in $Expected) {
    $key = $baseKey.OpenSubKey("$Prefix\$($e.Path)")
    Assert-Test ($null -ne $key) "${File}: key $($e.Path) was not created."
    try {
      $actual = $key.GetValue($e.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      Assert-Test ($key.GetValueKind($e.Name) -eq [Microsoft.Win32.RegistryValueKind]$e.Kind) "${File}: $($e.Name) has the wrong type."
      Assert-Test ((@($actual) -join '|') -eq (@($e.Value) -join '|')) "${File}: $($e.Name) = $actual; expected $($e.Value)."
    }
    finally { $key.Dispose() }
  }
}

$fve = 'SOFTWARE\Policies\Microsoft\FVE'
$cases = @(
  @{ File = '0482_Restrict_remotely_accessible_registry_paths.ps1'; Expected = @(
      @{ Path = 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'; Name = 'Machine'; Kind = 'MultiString'; Value = @(
          'System\CurrentControlSet\Control\ProductOptions', 'System\CurrentControlSet\Control\Server Applications', 'Software\Microsoft\Windows NT\CurrentVersion') },
      @{ Path = 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'; Name = 'Machine'; Kind = 'MultiString'; Value = @(
          'System\CurrentControlSet\Control\Print\Printers', 'System\CurrentControlSet\Services\Eventlog', 'Software\Microsoft\OLAP Server',
          'Software\Microsoft\Windows NT\CurrentVersion\Print', 'Software\Microsoft\Windows NT\CurrentVersion\Windows',
          'System\CurrentControlSet\Control\ContentIndex', 'System\CurrentControlSet\Control\Terminal Server',
          'System\CurrentControlSet\Control\Terminal Server\UserConfig', 'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration',
          'Software\Microsoft\Windows NT\CurrentVersion\Perflib', 'System\CurrentControlSet\Services\SysmonLog') }) },
  @{ File = '0483_Enforce_firewall_local_rule_merge_domain_private.ps1'; Expected = @(
      @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'AllowLocalPolicyMerge'; Kind = 'DWord'; Value = 1 },
      @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'AllowLocalIPsecPolicyMerge'; Kind = 'DWord'; Value = 1 },
      @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'AllowLocalPolicyMerge'; Kind = 'DWord'; Value = 1 },
      @{ Path = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'AllowLocalIPsecPolicyMerge'; Kind = 'DWord'; Value = 1 }) },
  @{ File = '0484_Harden_network_connections_policies.ps1'; Expected = @(
      @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name = 'NC_AllowNetBridge_NLA'; Kind = 'DWord'; Value = 0 },
      @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name = 'NC_StdDomainUserSetLocation'; Kind = 'DWord'; Value = 1 }) },
  @{ File = '0485_Enforce_registry_policy_processing.ps1'; Expected = @(
      @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Name = 'NoBackgroundPolicy'; Kind = 'DWord'; Value = 0 },
      @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Name = 'NoGPOListChanges'; Kind = 'DWord'; Value = 0 }) },
  @{ File = '0486_Block_user_input_methods_for_signin.ps1'; Expected = @(
      @{ Path = 'SOFTWARE\Policies\Microsoft\Control Panel\International'; Name = 'BlockUserInputMethodsForSignIn'; Kind = 'DWord'; Value = 1 }) },
  @{ File = '0488_Configure_BitLocker_OS_drive_recovery.ps1'; Expected = @(
      @{ Path = $fve; Name = 'OSRecovery'; Kind = 'DWord'; Value = 1 },
      @{ Path = $fve; Name = 'OSManageDRA'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'OSRecoveryPassword'; Kind = 'DWord'; Value = 2 },
      @{ Path = $fve; Name = 'OSRecoveryKey'; Kind = 'DWord'; Value = 2 },
      @{ Path = $fve; Name = 'OSHideRecoveryPage'; Kind = 'DWord'; Value = 1 }) },
  @{ File = '0489_Require_BitLocker_startup_PIN.ps1'; Expected = @(
      @{ Path = $fve; Name = 'UseAdvancedStartup'; Kind = 'DWord'; Value = 1 },
      @{ Path = $fve; Name = 'EnableBDEWithNoTPM'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'UseTPM'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'UseTPMPIN'; Kind = 'DWord'; Value = 1 },
      @{ Path = $fve; Name = 'UseTPMKey'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'UseTPMKeyPIN'; Kind = 'DWord'; Value = 0 }) },
  @{ File = '0490_Configure_BitLocker_removable_drives.ps1'; Expected = @(
      @{ Path = $fve; Name = 'RDVRecoveryPassword'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'RDVRecoveryKey'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'RDVHideRecoveryPage'; Kind = 'DWord'; Value = 1 },
      @{ Path = $fve; Name = 'RDVActiveDirectoryBackup'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'RDVActiveDirectoryInfoToStore'; Kind = 'DWord'; Value = 1 },
      @{ Path = $fve; Name = 'RDVRequireActiveDirectoryBackup'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'RDVPassphrase'; Kind = 'DWord'; Value = 0 },
      @{ Path = $fve; Name = 'RDVEnforceUserCert'; Kind = 'DWord'; Value = 1 },
      @{ Path = 'SYSTEM\CurrentControlSet\Policies\Microsoft\FVE'; Name = 'RDVDenyWriteAccess'; Kind = 'DWord'; Value = 1 }) }
)

function Invoke-Captured {
  param([scriptblock]$Block)
  return @(& $Block 6>&1 3>$null | ForEach-Object { "$_" })
}

function Assert-Status {
  param([string]$File, [string[]]$Output, [int]$Updated, [int]$Already)
  $u = @($Output | Where-Object { $_ -like '*[[]Was updated[]]*' }).Count
  $a = @($Output | Where-Object { $_ -like '*[[]Already configured[]]*' }).Count
  Assert-Test ($u -eq $Updated -and $a -eq $Already) "${File}: expected $Updated updated / $Already already configured, got $u / $a."
  Assert-Test (@($Output | Where-Object { $_ -like '*confirmed*' }).Count -eq 0) "${File}: ambiguous [confirmed] status still printed."
}

try {
  foreach ($case in $cases) {
    $prefix = "$testRoot\$($case.File)"
    $count = $case.Expected.Count
    $script:testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = '22000' }
    $block = Get-IsolatedScript -File $case.File -Prefix $prefix
    Assert-Status -File $case.File -Output (Invoke-Captured $block) -Updated $count -Already 0
    Assert-Values -File $case.File -Prefix $prefix -Expected $case.Expected
    Assert-Status -File $case.File -Output (Invoke-Captured $block) -Updated 0 -Already $count

    # Corrupt one value (wrong type and data), then rerun.
    $first = $case.Expected[0]
    $key = $baseKey.OpenSubKey("$prefix\$($first.Path)", $true)
    try { $key.SetValue($first.Name, 'tampered', [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
    $output = Invoke-Captured $block
    Assert-Status -File $case.File -Output $output -Updated 1 -Already ($count - 1)
    Assert-Test (@($output | Where-Object { $_ -like '*[[]Was updated[]]*tampered (String) -> *' }).Count -eq 1) "$($case.File): previous value not reported."
    Assert-Values -File $case.File -Prefix $prefix -Expected $case.Expected

    $baseKey.DeleteSubKeyTree($prefix, $false)
    foreach ($os in @([pscustomobject]@{ ProductType = 1; BuildNumber = '19045' }, [pscustomobject]@{ ProductType = 3; BuildNumber = '26100' })) {
      $script:testOS = $os
      $rejected = $false
      try { & $block | Out-Null } catch { $rejected = $_.Exception.Message -like '*Windows 11 is required*' }
      Assert-Test $rejected "$($case.File): unsupported OS was not rejected."
      Assert-Test ($null -eq $baseKey.OpenSubKey($prefix)) "$($case.File): unsupported OS wrote registry values."
    }
    Write-Host "[PASS] $($case.File)"
  }

  $dmaFile = '0487_Disable_new_DMA_devices_when_locked.ps1'
  $dmaExpected = @(@{ Path = $fve; Name = 'DisableExternalDMAUnderLock'; Kind = 'DWord'; Value = 1 })
  foreach ($state in @('false', 'true', 'null')) {
    $prefix = "$testRoot\$dmaFile-$state"
    $script:testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = '22000' }
    $block = Get-IsolatedScript -File $dmaFile -Prefix $prefix -Replacements @{
      '$kernelDmaProtection = Get-KernelDmaProtectionState' = "`$kernelDmaProtection = `$$state"
    }
    $output = Invoke-Captured $block
    if ($state -eq 'false') {
      Assert-Status -File $dmaFile -Output $output -Updated 1 -Already 0
      Assert-Values -File $dmaFile -Prefix $prefix -Expected $dmaExpected
      Assert-Status -File $dmaFile -Output (Invoke-Captured $block) -Updated 0 -Already 1
    }
    else {
      Assert-Test ($null -eq $baseKey.OpenSubKey($prefix)) "${dmaFile}: wrote the policy with Kernel DMA Protection state '$state'."
    }
  }
  Write-Host "[PASS] $dmaFile (Kernel DMA Protection off/on/unknown)"
}
finally {
  $baseKey.DeleteSubKeyTree($testRoot, $false)
  $baseKey.Dispose()
}

# 0491: auditpol is mocked with the real output formats; state is kept in memory.
$auditFile = '0491_Enable_audit_account_management_subcategories.ps1'
$auditBlock = [scriptblock]::Create([IO.File]::ReadAllText((Join-Path $defaultDir $auditFile)))
$expectedGuids = @('{0CCE9236-69AE-11D9-BED3-505054503030}', '{0CCE923A-69AE-11D9-BED3-505054503030}')
$script:backupFiles = New-Object System.Collections.ArrayList

function auditpol.exe {
  $joined = $args -join ' '
  if ($args[0] -eq '/backup') {
    if ($script:auditFail -eq 'backup') { $global:LASTEXITCODE = 5; return 'Error 0x00000005' }
    if ($joined -notmatch '^/backup /file:(.+\.csv)$') { $global:LASTEXITCODE = 87; return 'bad backup arguments' }
    $path = $Matches[1]
    [void]$script:backupFiles.Add($path)
    # Same layout as audit.csv: 7 localized columns, lowercase GUIDs, plus option rows.
    $lines = @('Nom de la machine,Cible de la stratégie,Sous-catégorie,GUID de sous-catégorie,Inclusion,Exclusion,Valeur du paramètre')
    foreach ($g in @('{0CCE9235-69AE-11D9-BED3-505054503030}') + $expectedGuids) {
      $value = if ($script:auditState.ContainsKey($g)) { $script:auditState[$g] } else { 0 }
      $lines += "PC,Système,Nom localisé,$($g.ToLowerInvariant()),Texte localisé,,$value"
    }
    $lines += 'PC,,Option:CrashOnAuditFail,,Désactivé,,0'
    [IO.File]::WriteAllLines($path, $lines, [Text.Encoding]::Unicode)
    $global:LASTEXITCODE = 0
    return 'La commande a été exécutée.'
  }
  if ($joined -notmatch '/subcategory:(\{[0-9A-F-]+\})') { $global:LASTEXITCODE = 87; return 'bad arguments' }
  $guid = $Matches[1]
  if ($args[0] -eq '/set') {
    if ($script:auditFail -eq 'set') { $global:LASTEXITCODE = 5; return 'Error 0x00000005' }
    if ($joined -ne "/set /subcategory:$guid /success:enable /failure:enable") { $global:LASTEXITCODE = 87; return 'bad set arguments' }
    if ($script:auditFail -ne 'verify') { $script:auditState[$guid] = 3 }
    $global:LASTEXITCODE = 0
    return 'The command was successfully executed.'
  }
  if ($args[0] -eq '/get' -and $args[2] -eq '/r') {
    # Real /r report: 6 columns, no numeric setting value.
    $global:LASTEXITCODE = 0
    return @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting', '', "PC,System,Localized name,$guid,Success and Failure,")
  }
  $global:LASTEXITCODE = 87
  return 'unexpected call'
}

$script:testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = '22000' }
$script:auditFail = $null
$script:auditState = @{}
$output = Invoke-Captured $auditBlock
Assert-Status -File $auditFile -Output $output -Updated 2 -Already 0
Assert-Test (@($output | Where-Object { $_ -like '*No Auditing -> Success and Failure*' }).Count -eq 2) "${auditFile}: previous state not reported."
foreach ($guid in $expectedGuids) { Assert-Test ($script:auditState[$guid] -eq 3) "${auditFile}: $guid not configured." }
Assert-Test ($script:auditState.Count -eq $expectedGuids.Count) "${auditFile}: unexpected subcategories configured."
Assert-Status -File $auditFile -Output (Invoke-Captured $auditBlock) -Updated 0 -Already 2
$script:auditState = @{ '{0CCE9236-69AE-11D9-BED3-505054503030}' = 1 }
$output = Invoke-Captured $auditBlock
Assert-Test (@($output | Where-Object { $_ -like '*Computer Account Management*: Success -> Success and Failure*' }).Count -eq 1) "${auditFile}: partial state not reported."
Assert-Test (@($script:backupFiles | Where-Object { Test-Path -LiteralPath $_ }).Count -eq 0) "${auditFile}: temporary backup files were left behind."
foreach ($failure in @('set', 'verify', 'backup')) {
  $script:auditFail = $failure
  $script:auditState = @{}
  $threw = $false
  try { & $auditBlock | Out-Null } catch { $threw = $true }
  Assert-Test $threw "${auditFile}: $failure failure was not reported."
}
$script:auditFail = $null
$script:testOS = [pscustomobject]@{ ProductType = 1; BuildNumber = '19045' }
$script:auditState = @{}
$rejected = $false
try { & $auditBlock | Out-Null } catch { $rejected = $_.Exception.Message -like '*Windows 11 is required*' }
Assert-Test ($rejected -and $script:auditState.Count -eq 0) "${auditFile}: unsupported OS was not rejected."
Write-Host "[PASS] $auditFile (localized CSV headers, set and verification failures)"
