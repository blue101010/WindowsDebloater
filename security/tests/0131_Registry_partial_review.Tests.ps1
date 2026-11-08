$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot '..\default\0131_hklm-cis-windows.reg'
$dscFile = Join-Path $PSScriptRoot '..\default\0205_Configure_CIS_Windows10_V181_DSC_hardening.ps1'
$source = [IO.File]::ReadAllText((Resolve-Path $file))
$dsc = [IO.File]::ReadAllText((Resolve-Path $dscFile))

if ($source -notmatch '^Windows Registry Editor Version 5\.00') { throw 'Registry header missing.' }
if ($source -match '(?im)^;?\[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\') {
  throw 'An Edge Legacy policy block remains.'
}

$resources = @{}
$resourcePattern = '(?ms)^\s*Registry\s+[^\r\n{]+\s*\{(?<body>.*?)^\s*\}'
foreach ($resource in [regex]::Matches($dsc, $resourcePattern)) {
  $body = $resource.Groups['body'].Value
  if ($body -notmatch "(?im)^\s*Ensure\s*=\s*'Present'") { continue }
  if ($body -notmatch "(?im)^\s*Key\s*=\s*'([^']+)'") { continue }
  $key = $Matches[1]
  if ($body -notmatch "(?im)^\s*ValueName\s*=\s*'([^']+)'") { continue }
  $name = $Matches[1]
  if ($body -notmatch "(?im)^\s*ValueType\s*=\s*'DWord'") { continue }
  if ($body -notmatch "(?im)^\s*ValueData\s*=\s*'([0-9]+)'") { continue }
  $resources["$key|$name|$([int64]$Matches[1])"] = $true
}
if ($resources.Count -lt 100) { throw 'DSC registry resources were not parsed.' }

$blocks = [regex]::Matches($source, '(?ms)^;;; \d[^\r\n]*(?:\r?\n).*?(?=^;;; \d|\z)')
foreach ($block in $blocks) {
  $keys = [regex]::Matches($block.Value, '(?im)^;?\[(HKEY_LOCAL_MACHINE[^]]+)\]')
  $values = [regex]::Matches($block.Value, '(?im)^;?"([^"]+)"=(.*)$')
  if ($keys.Count -ne 1 -or $values.Count -ne 1) { continue }
  $data = $values[0].Groups[2].Value.Trim()
  if ($data -notmatch '^dword:([0-9a-f]{1,8})$') { continue }
  $value = [Convert]::ToInt64($Matches[1], 16)
  $identity = '{0}|{1}|{2}' -f $keys[0].Groups[1].Value, $values[0].Groups[1].Value, $value
  if ($resources.ContainsKey($identity)) { throw "Exact single-value DSC duplicate remains: $identity" }
}
Write-Host '[PASS] No Edge Legacy blocks or single-value DWORD DSC duplicates remain.'
