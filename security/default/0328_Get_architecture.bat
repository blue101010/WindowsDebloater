@echo off
setlocal
:: PROCESSOR_ARCHITEW6432 identifies the native architecture from a 32-bit process.
set "architecture=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "architecture=%PROCESSOR_ARCHITEW6432%"
if not defined architecture (
  echo [0328_Get_architecture] [FAIL] Operating system architecture is unavailable.
  exit /b 1
)
echo OSArchitecture: %architecture%
exit /b 0