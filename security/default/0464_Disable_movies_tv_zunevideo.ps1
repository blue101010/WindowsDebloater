#  fully remove the Movies & TV app (formerly ZuneVideo) from the system

$patterns = @('*ZuneVideo*', '*Microsoft.ZuneVideo*')
$removed = $false

foreach ($pattern in $patterns) {
    $pkg = Get-AppxPackage $pattern -ErrorAction SilentlyContinue
    if ($pkg) {
        try {
            $pkg | Remove-AppxPackage -ErrorAction Stop
            Write-Host "[SUCCESS] Removed Movies & TV (ZuneVideo): $($pkg.Name)" -ForegroundColor Green
            $removed = $true
        } catch {
            Write-Host "[FAILED]  Could not remove $($pkg.Name): $_" -ForegroundColor Red
        }
    }
}

if (-not $removed) {
    Write-Host "[NO APP]  Movies & TV (ZuneVideo) not found - nothing to remove." -ForegroundColor Yellow
}