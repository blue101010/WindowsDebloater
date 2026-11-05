#
#https://support.microsoft.com/en-us/topic/understanding-get-speculationcontrolsettings-powershell-script-output-fd70a80a-a63f-e539-cda5-5be4c9e67c04

#Windows Server guidance to protect against speculative execution side-channel vulnerabilities  (SPECTRE)

#https://support.microsoft.com/en-us/topic/windows-server-guidance-to-protect-against-speculative-execution-side-channel-vulnerabilities-2f965763-00e2-8f98-b632-0d96f30c8c8e

#https://community.tenable.com/s/article/Speculative-Execution-Side-Channel-Vulnerability-Plugin-and-Mitigation-Information

#https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)

#######
# For more information about the output below, please refer to https://support.microsoft.com/help/4074629
# Speculation control settings for CVE-2017-5715 [branch target injection]
# Hardware support for branch target injection mitigation is present: True
# Windows OS support for branch target injection mitigation is present: True
# Windows OS support for branch target injection mitigation is enabled: True
# Speculation control settings for CVE-2017-5754 [rogue data cache load]
# Hardware requires kernel VA shadowing: True
# Windows OS support for kernel VA shadow is present: True
# Windows OS support for kernel VA shadow is enabled: True
# Windows OS support for PCID performance optimization is enabled: True [not required for security]
#######

# Installs for the current user only when missing; requires PowerShell Gallery access.
if (-not (Get-Module -ListAvailable -Name SpeculationControl -ErrorAction Stop)) {
    Install-Module -Name SpeculationControl -Scope CurrentUser -ErrorAction Stop
}
Import-Module -Name SpeculationControl -ErrorAction Stop
Get-SpeculationControlSettings -ErrorAction Stop