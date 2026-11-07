:: Disable Edge password manager to encourage use of proper password manager
:: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.MicrosoftEdge::AllowPasswordManager
:: @N@Disable_Edge_password_manager@N@
:: @@@Microsoft Edge@@@ @@@FormSuggest Passwords@@@
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f

      @REM # 18.9.45.6 (L1) Ensure 'Configure Password Manager' is set to 'Disabled'
      @REM Registry 'FormSuggestPasswords' {
      @REM     Ensure     = 'Present'
      @REM     Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main'
      @REM     ValueName  = 'FormSuggest Passwords'
      @REM     ValueType  = 'String'
      @REM     ValueData  = 'no'
      @REM }

@REM #Configure Password Manager'
@REM $indextest += 1
@REM $chaine = $null
@REM $traitement = $null
@REM $id = "ME" + "$indextest"
@REM $chaine = "$id" + ";" + "(L1)Ensure 'Configure Password Manager' is set to 'Disabled', value must be 0 " + ";"
@REM $exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
@REM if ( $exist -eq $true) {
@REM  $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" |Select-Object FormSuggestPasswords
@REM  $traitement = $traitement.FormSuggestPasswords
@REM }
@REM else {
@REM  $traitement = "not configure"
@REM }
@REM $chaine += $traitement
@REM $chaine>> $nomfichier

@REM ;;; 18.9.45.5 (L1) Ensure 'Configure Password Manager' is set to 'Disabled'
@REM ;[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main]
@REM ; <deleted> = (Default)
@REM ; no = Off (CIS)
@REM ; yes = On
@REM ; NON-COMPLIANCE TO NOT DISRUPT COMMON HOME FEATURES
@REM ;"FormSuggest Passwords"="no"
