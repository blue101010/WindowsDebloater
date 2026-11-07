::#######################################################################
:: Enable and configure Windows Defender and advanced settings
::#######################################################################
::
:: Reset Defender to defaults. Commented out but available for reference
::"%programfiles%"\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
::
:: Start Defender Service
sc start WinDefend
::Enable Windows Defender sandboxing
setx /M MP_FORCE_USE_SANDBOX 1
:: Update signatures
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: Enable Defender periodic scanning
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
:: Enable Cloud functionality of Windows Defender
powershell.exe Set-MpPreference -MAPSReporting Advanced
powershell.exe Set-MpPreference -SubmitSamplesConsent Always
::
:: Enable early launch antimalware driver for scan of boot-start drivers
:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
::
:: Enable ASR rules in Win10 1903 ExploitGuard to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
::
:: Block Office Child Process Creation 
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
:: Block Process Injection
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
:: Block Win32 API calls in macros
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
:: Block Office from creating executables
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
:: Block lsass cred theft
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
:: Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Defender exploit system-wide protection
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,CFG,TerminateOnError
::