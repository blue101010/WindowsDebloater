# Windows 10 Pro / Enterprise
#Attack surface reduction
#Customize attack surface reduction rules
#Block Process Injection
#RULE : Block Office applications from injecting code into other processes	
#GUID : 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
# Run as Administrator. Read back this rule to confirm Enabled (1).
$ruleId = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
$preferences = Get-MpPreference -ErrorAction Stop
$ruleIds = @($preferences.AttackSurfaceReductionRules_Ids)
$ruleActions = @($preferences.AttackSurfaceReductionRules_Actions)
$ruleIndex = -1
for ($i = 0; $i -lt $ruleIds.Count; $i++) {
    if ($ruleIds[$i] -eq $ruleId) {
        $ruleIndex = $i
        break
    }
}
if ($ruleIds.Count -ne $ruleActions.Count -or $ruleIndex -lt 0) {
    throw "[0193_Enable_AttackSurfaceReductionRules_Block_Process_Injection] Verification failed: ASR rule $ruleId is missing or its action cannot be determined."
}
$status = $ruleActions[$ruleIndex]
if ($status -ne 1) {
    throw "[0193_Enable_AttackSurfaceReductionRules_Block_Process_Injection] Verification failed: ASR rule $ruleId action = '$status'; expected Enabled (1)."
}
Write-Host "[0193_Enable_AttackSurfaceReductionRules_Block_Process_Injection] [confirmed] Block Office applications from injecting code into other processes ($ruleId) = Enabled (1)."

#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/customize-attack-surface-reduction

#https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf

#https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/threat-protection/microsoft-defender-atp/customize-attack-surface-reduction.md