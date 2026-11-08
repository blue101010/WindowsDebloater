# Windows 11: restore the classic right-click context menu in Explorer.
# Disables "Show more options" by setting the InprocServer32 default value to an empty string.
# https://www.winhelponline.com/blog/get-classic-full-context-menu-windows-11/

$registryPath = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'

try {
    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
    Set-Item -Path $registryPath -Value '' -ErrorAction Stop

    $defaultValue = (Get-Item -Path $registryPath -ErrorAction Stop).GetValue('')
    if ($null -eq $defaultValue -or $defaultValue -ne '') {
        throw 'The InprocServer32 default value was not set to an empty string.'
    }

    Write-Host '[0289_Misc_Restore_classic_context_menu_Windows_11] Classic context menu enabled.' -ForegroundColor Green
}
catch {
    Write-Error "[0289_Misc_Restore_classic_context_menu_Windows_11] Failed to enable the classic context menu: $($_.Exception.Message)"
    exit 1
}
