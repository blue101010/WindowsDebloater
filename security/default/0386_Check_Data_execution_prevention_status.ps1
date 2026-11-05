<#
.SYNOPSIS
Checks the status of Data Execution Prevention (DEP) on the current operating system.
0: DEP is disabled for all processes.
1: DEP is enabled for all processes.
2: DEP is enabled for only Windows system components and services. (Default)
3: DEP is enabled for all processes, but some exceptions are allowed.

.DESCRIPTION
Uses Get-CimInstance to read DataExecutionPrevention_SupportPolicy from
Win32_OperatingSystem and reports the current policy with its description.
Missing or unknown values and query errors stop execution. No settings are changed.

.PARAMETER None

.EXAMPLE
Returns the current status of Data Execution Prevention (DEP) on the operating system.

#>
$os = Get-CimInstance -ClassName Win32_OperatingSystem -Property DataExecutionPrevention_SupportPolicy -ErrorAction Stop
$policy = $os.DataExecutionPrevention_SupportPolicy
$descriptions = @{
    0 = "DEP is disabled for all processes."
    1 = "DEP is enabled for all processes."
    2 = "DEP is enabled for only Windows system components and services. (Default)"
    3 = "DEP is enabled for all processes, but some exceptions are allowed."
}
if ($null -eq $policy -or $policy -notin @(0, 1, 2, 3)) {
    throw "[0386_Check_Data_execution_prevention_status] Cannot determine DEP status: unexpected policy '$policy'."
}
Write-Output "[0386_Check_Data_execution_prevention_status] DataExecutionPrevention_SupportPolicy = $policy : $($descriptions[[int]$policy])"
