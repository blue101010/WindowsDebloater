
:: Privacy - Prevent data collection in Edge, and generally improve privacy.
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI"
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableRecentApps" /t REG_DWORD /d 1 /f
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI"