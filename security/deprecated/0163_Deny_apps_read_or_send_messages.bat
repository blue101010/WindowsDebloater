::@N@0163_Deny_apps_read_or_send_messages@N@
::@@@DeviceAccess@@@ @@@Apps Access@@@
::@RO@0162_Allow_global_apps_use_your_camera.bat@RC@
::@@@DeviceAccess@@@ @@@Let apps read or send messages (text or MMS)@@@  @@@Let apps access text/mms@@@
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v "Value" /t REG_SZ /d "Deny" /f
::
:: https://techcult.com/wiki/allow-or-deny-apps-access-to-camera-in-windows-10/#Method_2_Allow_or_Deny_Apps_Access_to_Camera_using_Registry
:: https://www.joseespitia.com/2017/03/06/registry-keys-for-windows-10-privacy-settings/
:: https://eddiejackson.net/wp/?p=16373
:: https://raw.githubusercontent.com/NetwOrchestration/DWS_Neutralizer/master/DWS_Neutralizer.cmd



