function Set-TailscaleStartupType {
    [CmdletBinding()]
    param(
        [ValidateSet('OnDemand','Enabled','Disabled')]
        [string]$Mode = 'OnDemand',          # default

        [string]$ServiceName = 'Tailscale'   # adjust if different on your system
    )

    switch ($Mode) {
        'OnDemand' { $startValue = 'demand'   }
        'Enabled'  { $startValue = 'auto'     }
        'Disabled' { $startValue = 'disabled' }
    }

    sc.exe config $ServiceName start= $startValue | Out-Null

    # Read back effective mode from WMI/CIM
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    $effective = $svc.StartMode   # values like Automatic, Manual, Disabled[web:81][web:91]

    Write-Host ("Tailscale service '{0}' startup type set to: {1} (requested: {2})" -f `
                $ServiceName, $effective, $Mode)
}

# Default (OnDemand)
#Set-TailscaleStartupType

# Explicit calls
Set-TailscaleStartupType -Mode OnDemand
#Set-TailscaleStartupType -Mode Enabled
#Set-TailscaleStartupType -Mode Disabled
