:: Deny apps sync LooselyCoupled
::@@@[b1607] Let your apps automatically share and sync info with wireless devices tat don’t explicitly pair with your PC, tablet or phone@@@
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f 