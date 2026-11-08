$ErrorActionPreference = 'Stop'
$defaultDir = Join-Path $PSScriptRoot '..\default'
$scripts = @(Get-ChildItem -LiteralPath $defaultDir -Filter '0132.*_Disable_windows_feature_*.ps1' | Sort-Object Name)

function Assert-Test {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

Assert-Test ($scripts.Count -eq 92) "Expected 92 feature scripts, found $($scripts.Count)."
Assert-Test (-not (Test-Path -LiteralPath (Join-Path $defaultDir '0132_Disable_windows-features.bat'))) 'The original batch file is still present.'

$adminToken = '$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'

function Get-WindowsOptionalFeature {
  param([switch]$Online, $FeatureName, $ErrorAction)
  if (-not $script:features.ContainsKey($FeatureName)) {
    if ($ErrorAction -eq 'SilentlyContinue') { return $null }
    throw "Feature name $FeatureName is unknown."
  }
  [pscustomobject]@{ FeatureName = $FeatureName; State = $script:features[$FeatureName] }
}

function Disable-WindowsOptionalFeature {
  param([switch]$Online, $FeatureName, [switch]$NoRestart, $ErrorAction)
  Assert-Test $NoRestart "Disable-WindowsOptionalFeature called without -NoRestart for $FeatureName."
  $script:calls++
  if (-not $script:failVerify) { $script:features[$FeatureName] = $script:newState }
  [pscustomobject]@{ RestartNeeded = $script:restartNeeded }
}

function Enable-WindowsOptionalFeature {
  param([switch]$Online, $FeatureName, [switch]$All, [switch]$NoRestart, $ErrorAction)
  Assert-Test ($NoRestart -and $All) "Enable-WindowsOptionalFeature called without -All -NoRestart for $FeatureName."
  $script:enableCalls++
  if (-not $script:failVerify) { $script:features[$FeatureName] = $script:newState }
  [pscustomobject]@{ RestartNeeded = $script:restartNeeded }
}

function Invoke-Captured {
  param([scriptblock]$Block, [switch]$Enable)
  @(& $Block -Enable:$Enable 6>&1 | ForEach-Object { "$_" })
}

$seen = @{}
foreach ($file in $scripts) {
  Assert-Test ($file.Name -match '^0132\.(\d{3})_Disable_windows_feature_(.+)\.ps1$') "Unexpected name: $($file.Name)."
  $feature = $Matches[2]
  Assert-Test (-not $seen.ContainsKey($feature)) "Duplicate feature: $feature."
  $seen[$feature] = $true

  $source = [IO.File]::ReadAllText($file.FullName)
  Assert-Test ($source.Contains("`$featureName = `"$feature`"")) "$($file.Name): feature name does not match the file name."
  Assert-Test ($source.Contains($adminToken)) "$($file.Name): missing administrator check."
  $block = [scriptblock]::Create($source.Replace($adminToken, '$true'))

  $script:failVerify = $false
  $script:restartNeeded = $false
  $script:newState = 'Disabled'

  $script:features = @{ $feature = 'Enabled' }; $script:calls = 0
  $out = Invoke-Captured $block
  Assert-Test ($script:calls -eq 1 -and $out -like '*[[]Was updated[]]*Enabled -> Disabled' -and $out -notlike '*restart*') "$($file.Name): enabled feature not disabled."

  $script:calls = 0
  $out = Invoke-Captured $block
  Assert-Test ($script:calls -eq 0 -and $out -like '*[[]Already configured[]]*state = Disabled') "$($file.Name): repeat run changed the feature."

  $script:features = @{ $feature = 'DisabledWithPayloadRemoved' }
  $out = Invoke-Captured $block
  Assert-Test ($script:calls -eq 0 -and $out -like '*[[]Already configured[]]*DisabledWithPayloadRemoved') "$($file.Name): removed payload not treated as disabled."

  $script:features = @{}
  $out = Invoke-Captured $block
  Assert-Test ($script:calls -eq 0 -and $out -like '*[[]Not available[]]*does not exist*') "$($file.Name): absent feature not reported."
  $script:enableCalls = 0
  $out = Invoke-Captured $block -Enable
  Assert-Test ($script:enableCalls -eq 0 -and $out -like '*[[]Not available[]]*') "$($file.Name): -Enable on absent feature not reported."

  $script:features = @{ $feature = 'DisabledWithPayloadRemoved' }; $script:newState = 'Enabled'
  $out = Invoke-Captured $block -Enable
  Assert-Test ($script:enableCalls -eq 1 -and $out -like '*[[]Was updated[]]*DisabledWithPayloadRemoved -> Enabled') "$($file.Name): -Enable did not enable the feature."
  $out = Invoke-Captured $block -Enable
  Assert-Test ($script:enableCalls -eq 1 -and $out -like '*[[]Already configured[]]*state = Enabled') "$($file.Name): -Enable repeat run changed the feature."
  $script:features = @{ $feature = 'Disabled' }; $script:newState = 'EnablePending'; $script:restartNeeded = $true
  $out = Invoke-Captured $block -Enable
  Assert-Test ($out -like '*[[]Was updated[]]*Disabled -> EnablePending (restart required)') "$($file.Name): -Enable pending restart not reported."
  $script:features = @{ $feature = 'Disabled' }; $script:failVerify = $true
  $threw = $false
  try { Invoke-Captured $block -Enable | Out-Null } catch { $threw = $_.Exception.Message -like '*could not enable*' }
  Assert-Test $threw "$($file.Name): -Enable verification failure not reported."
  $script:failVerify = $false; $script:restartNeeded = $false; $script:newState = 'Disabled'

  # A mistyped switch ("- Enable") must be rejected, not silently treated as disable.
  $script:features = @{ $feature = 'Enabled' }; $script:calls = 0; $script:enableCalls = 0
  $threw = $false
  try { & $block '-' 'Enable' 6>$null | Out-Null } catch { $threw = $true }
  Assert-Test ($threw -and $script:calls -eq 0 -and $script:enableCalls -eq 0) "$($file.Name): stray arguments were not rejected."

  $script:features = @{ $feature = 'Enabled' }; $script:restartNeeded = $true; $script:newState = 'DisablePending'
  $out = Invoke-Captured $block
  Assert-Test ($out -like '*[[]Was updated[]]*Enabled -> DisablePending (restart required)') "$($file.Name): pending restart not reported."

  $script:features = @{ $feature = 'Enabled' }; $script:failVerify = $true
  $threw = $false
  try { Invoke-Captured $block | Out-Null } catch { $threw = $_.Exception.Message -like '*Verification failed*' }
  Assert-Test $threw "$($file.Name): verification failure not reported."

  $nonAdmin = [scriptblock]::Create($source.Replace($adminToken, '$false'))
  $script:features = @{ $feature = 'Enabled' }; $script:calls = 0
  $threw = $false
  try { Invoke-Captured $nonAdmin | Out-Null } catch { $threw = $_.Exception.Message -like '*Administrator*' }
  Assert-Test ($threw -and $script:calls -eq 0) "$($file.Name): non-administrator run not rejected."
}
Write-Host "[PASS] $($scripts.Count) feature scripts: disable, -Enable, repeat, removed payload, not available, pending restart, verification failure, non-admin."
