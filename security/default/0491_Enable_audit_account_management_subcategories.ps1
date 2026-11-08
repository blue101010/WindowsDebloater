<#
.SYNOPSIS
Audits Computer Account Management and Other Account Management Events (success and failure).

.DESCRIPTION
CIS 17.2.x (L1), extracted from 0181_WynisWIN10-CISv1.0.ps1.
  Audit Computer Account Management       = Success and Failure
  Audit Other Account Management Events   = Success and Failure
Subcategories are addressed by GUID so the script works on any display language.

.NOTES
Windows 11 only; run as Administrator. Advanced audit policy only overrides legacy
category settings when SCENoApplyLegacyAuditPolicy = 1 (set by 0342 and 0205).
A domain Group Policy audit configuration can override these local settings.
The other account management subcategories are configured by
0205_Configure_CIS_Windows10_V181_DSC_hardening.ps1.
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
#>

$scriptName = "0491_Enable_audit_account_management_subcategories"
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
  throw "[$scriptName] Windows 11 is required."
}

$subcategories = [ordered]@{
  'Computer Account Management'     = '{0CCE9236-69AE-11D9-BED3-505054503030}'
  'Other Account Management Events' = '{0CCE923A-69AE-11D9-BED3-505054503030}'
}

$columns = 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'SettingValue'
function Get-AuditSettingValue {
  param([string]$Name, [string]$Guid)
  # "auditpol /get /r" has no numeric column and its text is localized; the /backup CSV
  # includes "Setting Value" (0 = No Auditing, 1 = Success, 2 = Failure, 3 = Both).
  $file = Join-Path ([IO.Path]::GetTempPath()) ("auditpol-$([guid]::NewGuid()).csv")
  try {
    $output = & auditpol.exe /backup "/file:$file" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "[$scriptName] auditpol /backup failed: $output" }
    # Columns are read by position because headers can be localized.
    $row = @(Get-Content -LiteralPath $file -ErrorAction Stop | Where-Object { $_ -match '\S' } |
        Select-Object -Skip 1 | ConvertFrom-Csv -Header $columns) |
      Where-Object { $_.Guid -eq $Guid } | Select-Object -First 1
  }
  finally {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
  }
  if ($null -eq $row -or [string]::IsNullOrWhiteSpace($row.SettingValue)) { return 0 }
  $value = 0
  if (-not [int]::TryParse($row.SettingValue.Trim(), [ref]$value)) {
    throw "[$scriptName] Unexpected audit setting for ${Name}: '$($row.SettingValue)'."
  }
  return $value
}

$labels = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
foreach ($name in $subcategories.Keys) {
  $guid = $subcategories[$name]
  $before = Get-AuditSettingValue -Name $name -Guid $guid
  if ($before -eq 3) {
    Write-Host "[$scriptName] [Already configured] $name $guid = Success and Failure"
    continue
  }

  $output = & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable 2>&1
  if ($LASTEXITCODE -ne 0) { throw "[$scriptName] auditpol /set failed for ${name}: $output" }
  if ((Get-AuditSettingValue -Name $name -Guid $guid) -ne 3) {
    throw "[$scriptName] Verification failed: $name is not audited for success and failure."
  }
  Write-Host "[$scriptName] [Was updated] $name ${guid}: $($labels[$before]) -> Success and Failure"
}
