@echo off
setlocal
:: Run as Administrator. Edge must be restarted for the policy to take effect.
:: This clears browsing data on exit, including passwords unless excluded by policy.
:: Force Clear Browsing Data on Close in Microsoft Edge for All Users
:: https://www.tenforums.com/tutorials/153307-turn-off-clear-browsing-data-close-microsoft-edge-chromium.html
:: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies

set "policyKey=HKLM\SOFTWARE\Policies\Microsoft\Edge"
reg add "%policyKey%" /v ClearBrowsingDataOnExit /t REG_DWORD /d 1 /f
if errorlevel 1 (
  echo [0310_Force_Clear_Browsing_Data_MS_Edge] [FAIL] Cannot set Edge policy. Run as Administrator.
  exit /b 1
)
reg query "%policyKey%" /v ClearBrowsingDataOnExit
if errorlevel 1 (
  echo [0310_Force_Clear_Browsing_Data_MS_Edge] [FAIL] Cannot read back Edge policy.
  exit /b 1
)
for /f "tokens=1,2,3" %%A in ('reg query "%policyKey%" /v ClearBrowsingDataOnExit 2^>nul') do (
  if /i "%%A"=="ClearBrowsingDataOnExit" if /i "%%B"=="REG_DWORD" if /i "%%C"=="0x1" (
    echo [0310_Force_Clear_Browsing_Data_MS_Edge] [confirmed] ClearBrowsingDataOnExit = 1. Restart Edge to apply.
    exit /b 0
  )
)
echo [0310_Force_Clear_Browsing_Data_MS_Edge] [FAIL] Verification failed: expected REG_DWORD 0x1.
exit /b 1
