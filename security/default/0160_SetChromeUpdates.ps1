# *******************************************
#
# Mod by: Jared M. Smith
# Mod on: 2015.04.xx
# Mod y?: Enable or disable Google Chrome updates.
#
# *******************************************

# Log method
if (! (test-path function:Log)) { function Log { Param([string]$message) Write-Host $message; } }

function SetChromeUpdates
{
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [boolean]$allowChromeUpdates
    )
    $updateText = "Enabling"
    
    # Enable/disable Chrome updates integer value
    $allowChromeUpdatesValue    = [int]$allowChromeUpdates
    $notAllowChromeUpdatesValue = [int]!$allowChromeUpdates #inverted value

    if (!$allowChromeUpdates) {
        $updateText = "Disabling"
    }
    
    Log "$updateText Google Chrome updates."   

    New-Item -Path HKLM:\SOFTWARE\Policies\Google -name Update -value $allowChromeUpdatesValue -Force
    New-Item -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Google -name Update -value $allowChromeUpdatesValue -Force

    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Update -type dword -name AutoUpdateCheckPeriodMinutes -value $allowChromeUpdatesValue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Update -type dword -name DisableAutoUpdateChecksCheckboxValue -value $notAllowChromeUpdatesValue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Update -type dword -name "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" -value $allowChromeUpdatesValue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Update -type dword -name UpdateDefault -value $allowChromeUpdatesValue -Force

    New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Google\Update -type dword -name AutoUpdateCheckPeriodMinutes -value $allowChromeUpdatesValue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Google\Update -type dword -name DisableAutoUpdateChecksCheckboxValue -value $notAllowChromeUpdatesValue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Google\Update -type dword -name "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" -value $allowChromeUpdatesValue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Google\Update -type dword -name UpdateDefault -value $allowChromeUpdatesValue -Force

    Log "Added registry keys for $updateText Google updates."

    if ($allowChromeUpdates) {
        Start-Service gupdate
        Start-Service gupdatem
        Log "Attempted to start Google update services(s)."
    }
    else {
        Stop-Service gupdate
        Stop-Service gupdatem
        Log "Stopped Google update services(s)."
    }
}
