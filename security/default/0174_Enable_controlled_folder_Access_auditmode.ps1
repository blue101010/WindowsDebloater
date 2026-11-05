# Run as Administrator. Read back the preference to confirm AuditMode (2).
Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction Stop
$preferences = Get-MpPreference -ErrorAction Stop
$status = $preferences.EnableControlledFolderAccess
if ($status -ne 2) {
    throw "[0174_Enable_controlled_folder_Access_auditmode] Verification failed: Controlled Folder Access = '$status'; expected AuditMode (2)."
}
Write-Host "[0174_Enable_controlled_folder_Access_auditmode] [confirmed] Controlled Folder Access = AuditMode (2). Events are audited, not blocked."
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-controlled-folders
#https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDefender::ExploitGuard_ControlledFolderAccess_EnableControlledFolderAccess