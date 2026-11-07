
:: Configure_Windows_Defender_SmartScreen
:: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.MicrosoftEdge::AllowSmartScreen
:: https://admx.help/HKCU/Software/Policies/Microsoft/MicrosoftEdge/PhishingFilter

::  Windows Defender SmartScreen provides warning messages 
::If you enable this setting, Windows Defender SmartScreen is turned on and employees can't turn it off.
::If you disable this setting, Windows Defender SmartScreen is turned off and employees can't turn it on.
::If you don't configure this setting, employees can choose whether to use Windows Defender SmartScreen.
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f


reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f


reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f


      @REM # 18.9.80.2.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'
      @REM Registry 'EnabledV9' {
      @REM     Ensure     = 'Present'
      @REM     Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
      @REM     ValueName  = 'EnabledV9'
      @REM     ValueType  = 'DWord'
      @REM     ValueData  = '1'
      @REM }   


@REM ;;; 18.9.80.2.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'
@REM [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
@REM ; <deleted> = (Default)
@REM ; 0000000 = Off
@REM ; 0000001 = On (Default / CIS)
@REM "EnabledV9"=dword:0000001


@REM #Configure SmartScreen Filter'
@REM $indextest += 1
@REM $chaine = $null
@REM $traitement = $null
@REM $id = "WDEF" + "$indextest"
@REM $chaine = "$id" + ";" + "(L1)Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled', value must be 1 " + ";"
@REM $exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
@REM if ( $exist -eq $true) {
@REM  $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" |Select-Object EnabledV9
@REM  $traitement = $traitement.EnabledV9
@REM }
@REM else {
@REM  $traitement = "not configure"
@REM }
@REM $chaine += $traitement
@REM $chaine>> $nomfichier


@REM # Disable SmartScreen Filter
@REM Function DisableSmartScreen {
@REM 	Write-Output "Disabling SmartScreen Filter..."
@REM 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
@REM 	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
@REM 		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
@REM 	}
@REM 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
@REM }


@REM # Enable SmartScreen Filter
@REM Function EnableSmartScreen {
@REM 	Write-Output "Enabling SmartScreen Filter..."
@REM 	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
@REM 	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
@REM }
