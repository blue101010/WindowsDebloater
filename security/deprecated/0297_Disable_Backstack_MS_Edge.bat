:: Turn off switching between recent apps
:: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.EdgeUI::TurnOffBackstack
::If you enable this setting, users will not be allowed to switch between recent apps. The App Switching option in the PC settings app will be disabled as well.

::If you disable or do not configure this policy setting, users will be allowed to switch between recent apps.


reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI"
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI" /v "TurnOffBackstack" /t REG_DWORD /d 1 /f
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI"