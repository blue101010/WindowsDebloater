function Set-TailscaleStartupType {
    [CmdletBinding()]
    param(
        [ValidateSet('OnDemand','Enabled','Disabled')]
        [string]$Mode = 'OnDemand',

        [string]$ServiceName = 'Tailscale'
    )

    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $existingSvc) {
        Write-Warning "Service '$ServiceName' not found."
        return
    }

    switch ($Mode) {
        'OnDemand' { $startValue = 'demand'   }
        'Enabled'  { $startValue = 'auto'     }
        'Disabled' { $startValue = 'disabled' }
    }

    sc.exe config $ServiceName start= $startValue | Out-Null

    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    $effective = $svc.StartMode

    Write-Host ("Tailscale service '{0}' startup type set to: {1} (requested: {2})" -f `
                $ServiceName, $effective, $Mode)
}

function Get-TailscaleServiceStatus {
    [CmdletBinding()]
    param(
        [string]$ServiceName = 'Tailscale'
    )

    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"

    if (-not $svc) {
        Write-Warning "Service '$ServiceName' not found."
        return
    }

    Write-Host ("Service: {0}" -f $svc.Name)
    Write-Host ("  State     : {0}" -f $svc.State)
    Write-Host ("  StartMode : {0}" -f $svc.StartMode)
    Write-Host ("  Status    : {0}" -f $svc.Status)
}

function Stop-TailscaleService {
    [CmdletBinding()]
    param(
        [string]$ServiceName = 'Tailscale'
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Warning "Service '$ServiceName' not found."
        return
    }

    if ($svc.Status -eq 'Stopped') {
        Write-Host ("Service '{0}' is already stopped." -f $ServiceName)
        return
    }

    if (-not (Test-IsAdministrator)) {
        Write-Warning "Stopping services requires elevation. Prompting for UAC consent..."
        Invoke-ElevatedServiceStop -ServiceName $ServiceName
        return
    }

    Invoke-LocalServiceStop -ServiceName $ServiceName
}

function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-LocalServiceStop {
    param(
        [string]$ServiceName
    )

    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        Write-Host ("Service '{0}' stopped." -f $ServiceName)
    }
    catch {
        Write-Warning ("Failed to stop service '{0}' via Stop-Service: {1}" -f $ServiceName, $_.Exception.Message)
        try {
            sc.exe stop $ServiceName | Out-Null
            Write-Host ("Service '{0}' stop command sent via sc.exe." -f $ServiceName)
        }
        catch {
            Write-Warning ("Fallback stop attempt failed for service '{0}': {1}" -f $ServiceName, $_.Exception.Message)
        }
    }
}

function Invoke-ElevatedServiceStop {
    param(
        [string]$ServiceName
    )

    $scriptBlock = @"
try {
    Stop-Service -Name '$ServiceName' -Force -ErrorAction Stop
    Write-Host "Service '$ServiceName' stopped (elevated instance)."
    exit 0
}
catch {
    Write-Error "Failed to stop service '$ServiceName': $($_.Exception.Message)"
    exit 1
}
"@

    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock))

    try {
        Write-Host "Requesting elevation in 3 seconds so you can see the UAC prompt..."
        for ($i = 3; $i -ge 1; $i--) {
            Write-Host ("  Elevation request in {0} second(s)..." -f $i)
            Start-Sleep -Seconds 1
        }

        $proc = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand `
            -Verb RunAs -Wait -PassThru

        if ($proc.ExitCode -eq 0) {
            Write-Host "Elevated stop completed successfully."
        }
        else {
            Write-Warning ("Elevated stop process exited with code {0}. Check the elevated window for details." -f $proc.ExitCode)
        }
    }
    catch {
        Write-Warning ("Could not obtain elevation to stop service '{0}': {1}" -f $ServiceName, $_.Exception.Message)
    }
}

function Show-TailscaleMenu {
    param(
        [string]$ServiceName = 'Tailscale'
    )

    do {
        Write-Host "================ Tailscale Service Menu ================"
        Write-Host "1) Check service status"
        Write-Host "2) Set startup type to OnDemand"
        Write-Host "3) Set startup type to Enabled"
        Write-Host "4) Set startup type to Disabled"
        Write-Host "5) Stop service"
        Write-Host "Q) Quit"
        $choice = Read-Host 'Select an option'

        switch ($choice.ToUpperInvariant()) {
            '1' {
                Get-TailscaleServiceStatus -ServiceName $ServiceName
                Wait-ForMenuResume
            }
            '2' {
                Set-TailscaleStartupType -Mode OnDemand -ServiceName $ServiceName
                Wait-ForMenuResume
            }
            '3' {
                Set-TailscaleStartupType -Mode Enabled -ServiceName $ServiceName
                Wait-ForMenuResume
            }
            '4' {
                Set-TailscaleStartupType -Mode Disabled -ServiceName $ServiceName
                Wait-ForMenuResume
            }
            '5' {
                Stop-TailscaleService -ServiceName $ServiceName
                Wait-ForMenuResume
            }
            'Q' {
                Write-Host 'Exiting menu.'
            }
            Default {
                Write-Warning 'Invalid selection. Please choose a valid option.'
            }
        }
    } while ($choice.ToUpperInvariant() -ne 'Q')
}

function Wait-ForMenuResume {
    Read-Host "Press Enter to return to the menu" | Out-Null
    Write-Host
}

if ($MyInvocation.InvocationName -ne '.') {
    Show-TailscaleMenu
}
