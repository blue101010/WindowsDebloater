# Run as Administrator. Read back the preference to confirm Enabled (1).
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
$preferences = Get-MpPreference -ErrorAction Stop
$status = $preferences.EnableControlledFolderAccess
if ($status -ne 1) {
    throw "[0175_Enable_controlled_folder_Access_enabled] Verification failed: Controlled Folder Access = '$status'; expected Enabled (1)."
}
Write-Host "[0175_Enable_controlled_folder_Access_enabled] [confirmed] Controlled Folder Access = Enabled (1). Unauthorized changes to protected folders are blocked."