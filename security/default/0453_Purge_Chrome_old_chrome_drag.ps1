# Purge old "chrome_drag*" files and directories from the local temp folder

[CmdletBinding()]
param(
    [int]$Days = 7,
    [string]$Path = "$env:LOCALAPPDATA\Temp"
)

$title = "[0453_Purge_Chrome_old_chrome_drag]"
$now = Get-Date
$cutoff = $now.AddDays(-$Days)

Write-Host "$title Start: $($now.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "$title Target path: $Path"
Write-Host "$title Retention: keep last $Days day(s), delete older than $($cutoff.ToString('yyyy-MM-dd HH:mm:ss'))"

if (-not (Test-Path -Path $Path)) {
    Write-Warning "$title Path not found: $Path"
    return
}

$allMatches = @(Get-ChildItem -Path $Path -Filter 'chrome_drag*' -Force -ErrorAction SilentlyContinue)
$toDelete = @($allMatches | Where-Object { $_.LastWriteTime -lt $cutoff } | Sort-Object LastWriteTime)

Write-Host ""
Write-Host "$title Present matches: $($allMatches.Count)"
if ($allMatches.Count -gt 0) {
    $allMatches |
        Sort-Object LastWriteTime |
        Select-Object FullName, @{Name="ItemType";Expression={ if ($_.PSIsContainer) { "Directory" } else { "File" } }}, LastWriteTime, CreationTime |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "$title Deletion candidates (older than cutoff): $($toDelete.Count)"
if ($toDelete.Count -gt 0) {
    $toDelete |
        Select-Object FullName, @{Name="ItemType";Expression={ if ($_.PSIsContainer) { "Directory" } else { "File" } }}, LastWriteTime, CreationTime |
        Format-Table -AutoSize
}

$deleted = @()
$failed = @()

foreach ($item in $toDelete) {
    try {
        if ($item.PSIsContainer) {
            Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
        } else {
            Remove-Item -Path $item.FullName -Force -ErrorAction Stop
        }
        $deleted += [pscustomobject]@{
            FullName = $item.FullName
            ItemType = if ($item.PSIsContainer) { "Directory" } else { "File" }
            LastWriteTime = $item.LastWriteTime
            DeletedAt = Get-Date
        }
    } catch {
        $failed += [pscustomobject]@{
            FullName = $item.FullName
            ItemType = if ($item.PSIsContainer) { "Directory" } else { "File" }
            LastWriteTime = $item.LastWriteTime
            Error = $_.Exception.Message
        }
    }
}

Write-Host ""
Write-Host "$title Deleted: $($deleted.Count)"
if ($deleted.Count -gt 0) {
    $deleted | Select-Object FullName, ItemType, LastWriteTime, DeletedAt | Format-Table -AutoSize
}

if ($failed.Count -gt 0) {
    Write-Warning "$title Failed deletions: $($failed.Count)"
    $failed | Select-Object FullName, ItemType, LastWriteTime, Error | Format-Table -AutoSize
}

Write-Host ""
Write-Host "$title Completed."
