::@@@Disable_submission_of_user_activities_into_the_cloud@@@
:: Ref 0075; 0131

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f

::[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
::"UploadUserActivities"=dword:00000000

:: https://www.tenforums.com/tutorials/110063-enable-disable-sync-activities-pc-cloud-windows-10-a.html#option2


::;;; 18.8.30.1 (L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'
::;[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
::; <deleted> = (Default)
::; 0000000 = Off (CIS)
::; 0000001 = On
::; NON-COMPLIANCE TO NOT DISRUPT COMMON HOME FEATURES
::;"UploadUserActivities"=dword:0000000