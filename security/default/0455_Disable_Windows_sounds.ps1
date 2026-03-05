# Set sound scheme to "No Sounds" for current user
Write-Host "Starting: Disable Windows sounds script." -ForegroundColor Cyan

$path = "HKCU:\AppEvents\Schemes"
$keyName = "(Default)"
$setValue = ".None"

if (-not (Test-Path $path)) {
    Write-Host "Path '$path' not found. Creating..." -ForegroundColor Yellow
    New-Item -Path $path -Force | Out-Null
    Write-Host "Path created." -ForegroundColor Green
}

$current = (Get-ItemProperty -Path $path -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($current -ne $setValue) {
    Write-Host "Current sound scheme is '$current'. Setting to '$setValue'..." -ForegroundColor Yellow
    Set-ItemProperty -Path $path -Name $keyName -Value $setValue
    Write-Host "Sound scheme updated." -ForegroundColor Green

    # Clear all per-event sounds
    Write-Host "Clearing all per-event sounds..." -ForegroundColor Yellow
    Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps" -Recurse |
        Where-Object { $_.PSChildName -eq ".Current" } |
        ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "(Default)" -Value ""
        }
    Write-Host "Per-event sounds cleared." -ForegroundColor Green
} else {
    Write-Host "Sound scheme is already set to '$setValue'. No changes needed." -ForegroundColor Gray
}

Write-Host "Completed: Disable Windows sounds script." -ForegroundColor Cyan
