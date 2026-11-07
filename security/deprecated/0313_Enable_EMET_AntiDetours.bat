:: Enable Enhanced Mitigation Experience Toolkit (EMET) AntiDetours
:: https://www.stigviewer.com/stig/windows_10/2016-11-03/finding/V-63417
:: https://admx.help/?Category=EMET&Policy=Microsoft.Policies.EMET::AdvancedConfiguration
:: https://www.tenable.com/audits/items/CIS_MS_Windows_7_v3.2.0_Level_1.audit:36aff4b0f24b05b516ed5fe5d4200c8e
:: These advanced mitigations for ROP mitigations apply to all configured software in EMET:
:: Anti Detours renders ineffective exploits that evade hooks by executing a copy of the hooked function prologue and then jump to the function past the prologue.


reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings"
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings" /v AntiDetours  /t REG_DWORD /d 1 /f
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings"





