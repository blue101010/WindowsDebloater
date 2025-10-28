<#
.SYNOPSIS
    Checks the status of Windows Recall feature and related AI data analysis settings.

.DESCRIPTION
    This script examines the Windows Recall feature configuration by checking:
    1. The Windows Optional Feature state for 'Recall'
    2. The AllowRecallEnablement registry policy setting
    3. The DisableAIDataAnalysis registry policy setting
    
    Windows Recall is a feature that captures screenshots and uses AI to analyze user activity
    for searchable history. This script helps determine if these privacy-sensitive features
    are properly disabled.

.PARAMETER None
    This script does not accept any parameters.

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    System.String
    Returns a JSON string containing the compliance summary with the following properties:
    - "Windows Recall Feature": Status of the Windows Optional Feature (Enabled/Disabled)
    - "Windows Recall AllowRecallEnablement": Registry policy status (Enabled/Disabled)
    - "Windows Recall DisableAIDataAnalysis": AI data analysis policy status (Enabled/Disabled)

.NOTES
    - Requires administrative privileges to read registry keys and Windows Optional Features
    - Registry keys checked:
      * HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\AllowRecallEnablement
      * HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis
    - For privacy compliance, all three settings should show "Disabled" for the feature
      and "Enabled" for the DisableAIDataAnalysis policy

.EXAMPLE
    PS C:\> .\0438_Check_Disable_recall.ps1
    {"Windows Recall Feature":"Disabled","Windows Recall AllowRecallEnablement":"Disabled","Windows Recall DisableAIDataAnalysis":"Enabled"}

.EXAMPLE
    PS C:\> .\0438_Check_Disable_recall.ps1 | ConvertFrom-Json

    Windows Recall Feature                 : Disabled
    Windows Recall AllowRecallEnablement   : Disabled  
    Windows Recall DisableAIDataAnalysis   : Enabled

.LINK
    https://support.microsoft.com/en-us/windows/retrace-your-steps-with-recall-aa03f8a0-a78b-4b3e-b0a1-2eb8ac48701c
#>

$complianceSummary = New-Object -TypeName PSObject
$featureRecall = (Get-WindowsOptionalFeature -Online -FeatureName 'Recall')
if ($featureRecall.State -eq 'Enabled') {
    $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall Feature' -Value 'Enabled'
}
else {
    $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall Feature' -Value 'Disabled'
}

if ((Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\' -ErrorAction Ignore).Property -contains 'AllowRecallEnablement') {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\' -Name 'AllowRecallEnablement') -eq 0) {
        $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall AllowRecallEnablement' -Value 'Disabled'
    }
    else {
        $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall AllowRecallEnablement' -Value 'Enabled'
    }
}
else {
    $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall AllowRecallEnablement' -Value 'Enabled'
}

if ((Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\' -ErrorAction Ignore).Property -contains 'DisableAIDataAnalysis') {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\' -Name 'DisableAIDataAnalysis') -eq 1) {
        $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall DisableAIDataAnalysis' -Value 'Enabled'
    }
    else {
        $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall DisableAIDataAnalysis' -Value 'Disabled'
    }
}
else {
    $complianceSummary | Add-Member -MemberType NoteProperty -Name 'Windows Recall DisableAIDataAnalysis' -Value 'Disabled'
}

return $complianceSummary | ConvertTo-Json -Compress