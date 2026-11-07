
::@N@Allow_global_apps_use_your_camera@N@
::@@@DeviceAccess@@@ @@@Apps Access@@@ @@@camera@@@
::Allow
:: https://techcult.com/wiki/allow-or-deny-apps-access-to-camera-in-windows-10/#Method_2_Allow_or_Deny_Apps_Access_to_Camera_using_Registry
:: https://www.joseespitia.com/2017/03/06/registry-keys-for-windows-10-privacy-settings/
::Let apps use my camera
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Allow" /f

:: BUT DENY ALL POSSIBLE OTHER ACCESSES
:: @RO@0088_Disable_device_access_for_Universal_Apps@RC@