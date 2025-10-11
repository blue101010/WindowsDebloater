# Check Wi-Fi adapter details
$wifi = Get-NetAdapter -Physical | Where-Object {$_.Name -like "*Wi-Fi*"}
If (-not $wifi) { Write-Host "No Wi-Fi adapter detected." ; exit }

Write-Host "Wi-Fi Adapter Detected: $($wifi.Name)"
Write-Host "Status: $($wifi.Status)"

# Check current connection and security type
$profiles = netsh wlan show interfaces
$auth = ($profiles | Select-String "Authentication").Line
$encryption = ($profiles | Select-String "Cipher").Line
$SSID = ($profiles | Select-String "SSID                   : ").Line

Write-Host "Current SSID: $SSID"
Write-Host "Authentication Type: $auth"
Write-Host "Encryption Type: $encryption"

# Check if DNS is set and whether using DoH
$dns = Get-DnsClientServerAddress -InterfaceAlias $wifi.Name
Write-Host "Configured DNS Servers: $($dns.ServerAddresses -join ', ')"

# Test connectivity and DNS resolution
Write-Host "`nTesting basic internet/DNS connectivity:"
Test-NetConnection -ComputerName www.google.com -InformationLevel "Detailed"

# Summarize recommendations
Write-Host "`nRecommended for CTF/Event Wi-Fi:"
Write-Host "- WPA2 or WPA3-Personal authentication"
Write-Host "- AES encryption (not TKIP)"
Write-Host "- DNS over HTTPS supported but not required for most events"
Write-Host "- Static DNS (e.g., 1.1.1.1 or 8.8.8.8) often recommended for reliability"

function Write-Item {
    param($label, $value, $color = 'White', $suffix = '')
    Write-Host ("{0,-28}: {1}{2}" -f $label, $value, $suffix) -ForegroundColor $color
}

function Get-NetshValue {
    param($lines, $label)
    # Find all matching lines for the label, extract values after the colon, trim and join them
    $matches = $lines | Where-Object { $_ -match "^\s*$([regex]::Escape($label))\s*:" }
    if ($matches) {
        $values = $matches | ForEach-Object { ($_ -replace '.*:\s*','').Trim() }
        return ($values -join ' | ')
    }
    return $null
}

# Find Wi‑Fi adapters
$wifiAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {
    ($_.Name -like '*Wi-Fi*') -or ($_.InterfaceDescription -match 'Wireless') -or ($_.InterfaceDescription -match 'Wi-Fi')
}

if (-not $wifiAdapters -or $wifiAdapters.Count -eq 0) {
    Write-Host "No Wi-Fi adapter detected." -ForegroundColor Yellow
    exit 0
}

foreach ($wifi in $wifiAdapters) {
    Write-Host "`n--- Wi‑Fi Adapter: $($wifi.Name) ---" -ForegroundColor Cyan

    # Basic adapter info
    Write-Item "Name" $wifi.Name 'White'
    Write-Item "InterfaceIndex" $wifi.ifIndex 'White'
    Write-Item "Status" $wifi.Status ($wifi.Status -eq 'Up' ? 'Green' : 'Red')
    Write-Item "LinkSpeed" $wifi.LinkSpeed 'White'
    Write-Item "MAC Address" $wifi.MacAddress 'White'
    Write-Item "InterfaceDescription" $wifi.InterfaceDescription 'White'

    # Netsh runtime wireless info
    $netsh = netsh wlan show interfaces 2>$null | ForEach-Object { $_.Trim() }
    $ssid = Get-NetshValue $netsh 'SSID'
    $bssid = Get-NetshValue $netsh 'BSSID'
    $radio = Get-NetshValue $netsh 'Radio type'
    $auth = Get-NetshValue $netsh 'Authentication'
    $cipher = Get-NetshValue $netsh 'Cipher'
    $channel = Get-NetshValue $netsh 'Channel'
    $signal = Get-NetshValue $netsh 'Signal'
    $rxRate = Get-NetshValue $netsh 'Receive rate (Mbps)'
    $txRate = Get-NetshValue $netsh 'Transmit rate (Mbps)'

    # Display runtime wireless info
    Write-Item "Current SSID" ($ssid ? $ssid : 'N/A') 'White'
    Write-Item "BSSID" ($bssid ? $bssid : 'N/A') 'White'
    Write-Item "Radio Type" ($radio ? $radio : 'N/A') 'White'
    # Security evaluation
    $secColor = 'Yellow'
    if ($auth) {
        if ($auth -match 'WPA3|WPA2|WPA-Personal') { $secColor='Green' }
        elseif ($auth -match 'WEP|Open') { $secColor='Red' }
        else { $secColor='Yellow' }
    }
    Write-Item "Authentication" ($auth ? $auth : 'N/A') $secColor
    Write-Item "Cipher" ($cipher ? $cipher : 'N/A') $secColor

    Write-Item "Channel" ($channel ? $channel : 'N/A') 'White'
    Write-Item "Signal" ($signal ? $signal : 'White')
    Write-Item "RX Rate (Mbps)" ($rxRate ? $rxRate : 'N/A') 'White'
    Write-Item "TX Rate (Mbps)" ($txRate ? $txRate : 'N/A') 'White'

    # IP configuration
    $ipcfg = Get-NetIPConfiguration -InterfaceIndex $wifi.ifIndex -ErrorAction SilentlyContinue
    if ($ipcfg) {
        $ipv4 = ($ipcfg.IPv4Address | Select-Object -First 1).IPv4Address
        $ipv6 = ($ipcfg.IPv6Address | Select-Object -First 1).IPv6Address
        $gw4 = ($ipcfg.IPv4DefaultGateway).NextHop
        $gw6 = ($ipcfg.IPv6DefaultGateway).NextHop
        Write-Host "`nIP Configuration:" -ForegroundColor Cyan
        Write-Item "IPv4 Address" ($ipv4 ? $ipv4 : 'None') 'White'
        Write-Item "IPv4 Gateway" ($gw4 ? $gw4 : 'None') 'White'
        Write-Item "IPv6 Address" ($ipv6 ? $ipv6 : 'None') 'White'
        Write-Item "IPv6 Gateway" ($gw6 ? $gw6 : 'None') 'White'
    } else {
        Write-Host "`nIP Configuration: N/A" -ForegroundColor Yellow
    }

    # DHCP and DNS details via WMI/CIM and ipconfig
    $wmi = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($wifi.ifIndex)" -ErrorAction SilentlyContinue
    if ($wmi) {
        $dhcpEnabled = $wmi.DHCPEnabled
        $dhcpServer = $wmi.DHCPServer
        $dhcpLeaseObtained = $wmi.DHCPLeaseObtained
        $dhcpLeaseExpires = $wmi.DHCPLeaseExpires
        $dnsServers = $wmi.DNSServerSearchOrder
        $dnsList = if ($dnsServers) { $dnsServers -join ', ' } else { '' }
        $dnsSuffix = $wmi.DNSDomain
        $dnsHostName = $wmi.DNSHostName
        $dnsSearchOrder = if ($wmi.DNSDomainSuffixSearchOrder) { $wmi.DNSDomainSuffixSearchOrder -join ', ' } else { $null }
        $registerAddress = $wmi.RegisterThisConnectionsAddress
        $useSuffixWhenRegistering = $wmi.UseSuffixWhenRegistering

        # Determine default flags: DHCP enabled => default, DNS via DHCP => default
        $dhcpColor = $dhcpEnabled ? 'DarkYellow' : 'Green'  # enabled is default -> DarkYellow
        Write-Host "`nAdapter Service Settings:" -ForegroundColor Cyan
        Write-Item "DHCP Enabled" ($dhcpEnabled ? 'Yes (default)' : 'No (static)') $dhcpColor
        Write-Item "DHCP Server" ($dhcpServer ? $dhcpServer : 'N/A') 'White'
        Write-Item "DHCP Lease Obtained" ($dhcpLeaseObtained ? $dhcpLeaseObtained : 'N/A') 'White'
        Write-Item "DHCP Lease Expires" ($dhcpLeaseExpires ? $dhcpLeaseExpires : 'N/A') 'White'

        if ($dnsList) {
            $dnsColor = ($dhcpEnabled -and $dnsList) ? 'DarkYellow' : 'Green'
            Write-Item "DNS Servers" $dnsList $dnsColor
        } else {
            Write-Item "DNS Servers" 'None' 'Yellow'
        }

        Write-Item "Primary DNS Suffix" ($dnsSuffix ? $dnsSuffix : 'N/A') 'White'
        Write-Item "DNS HostName" ($dnsHostName ? $dnsHostName : 'N/A') 'White'
        Write-Item "DNS Suffix Search Order" ($dnsSearchOrder ? $dnsSearchOrder : 'N/A') 'White'
        Write-Item "Register This Conn Address" ($registerAddress ? 'Yes' : 'No') 'White'
        Write-Item "Use Suffix When Reg." ($useSuffixWhenRegistering ? 'Yes' : 'No') 'White'

        # ipconfig /all excerpt for the interface to show DHCP/DNS lines
        $ipcfgAll = ipconfig /all
        $match = $ipcfgAll | Select-String -Pattern ([regex]::Escape($wifi.Name)) -Context 0,20 -SimpleMatch
        if ($match) {
            Write-Host "`nipconfig /all (interface excerpt):" -ForegroundColor Cyan
            $excerpt = $match.Context.PostContext
            $excerpt | Where-Object { $_ -match 'DNS Servers|DHCP Server|Lease Obtained|Lease Expires|Primary Dns Suffix|Connection-specific DNS Suffix' } |
                ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor Gray }
        } else {
            # fallback: try to match by interface description or interface index in ipconfig output
            $match2 = $ipcfgAll | Select-String -Pattern ("Interface Index\. .*$($wifi.ifIndex)|$($wifi.InterfaceDescription)") -Context 0,20
            if ($match2) {
                Write-Host "`nipconfig /all (interface excerpt):" -ForegroundColor Cyan
                $match2.Context.PostContext | Where-Object { $_ -match 'DNS Servers|DHCP Server|Lease Obtained|Lease Expires|Primary Dns Suffix|Connection-specific DNS Suffix' } |
                    ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor Gray }
            }
        }

        # Show example commands to change binding/DNS (unchanged)
        Write-Host "`nSuggested Commands (example):" -ForegroundColor Cyan
        if ($dhcpEnabled) {
            Write-Host "  Set static IPv4:" -ForegroundColor Gray
            Write-Host "    New-NetIPAddress -InterfaceIndex $($wifi.ifIndex) -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1" -ForegroundColor Gray
            Write-Host "  Set static DNS:" -ForegroundColor Gray
            Write-Host "    Set-DnsClientServerAddress -InterfaceIndex $($wifi.ifIndex) -ServerAddresses ('1.1.1.1','8.8.8.8')" -ForegroundColor Gray
        } else {
            Write-Host "  Revert to DHCP (IPv4):" -ForegroundColor Gray
            Write-Host "    Remove-NetIPAddress -InterfaceIndex $($wifi.ifIndex) -AddressFamily IPv4 -Confirm:$false ; Set-DnsClientServerAddress -InterfaceIndex $($wifi.ifIndex) -ResetServerAddresses" -ForegroundColor Gray
        }
    } else {
        Write-Host "`nCould not retrieve DHCP/DNS info via CIM for this interface." -ForegroundColor Yellow
    }

    # Profiles info (if any)
    $profiles = netsh wlan show profiles 2>$null | ForEach-Object { $_.Trim() }
    $profileLines = $profiles | Where-Object { $_ -match '^All User Profile' -or $_ -match '^User Profiles' -or $_ -match '^\s*Profile' }
    $currentProfile = $null
    if ($ssid) {
        # If a profile exists with same name
        $profileNameLine = ($profiles | Where-Object { $_ -match "^\s*All User Profile\s*:" -and ($_ -replace '.*:\s*','') -eq $ssid })
        if ($profileNameLine) { $currentProfile = $ssid }
    }
    if ($currentProfile) {
        Write-Host "`nProfile detected for SSID '$currentProfile'." -ForegroundColor Cyan
        # show basic profile security info
        $pf = netsh wlan show profile name="$currentProfile" key=clear 2>$null | ForEach-Object { $_.Trim() }
        $pfAuth = Get-NetshValue $pf 'Authentication'
        $pfCipher = Get-NetshValue $pf 'Cipher'
        Write-Item "Profile Authentication" ($pfAuth ? $pfAuth : 'N/A') ($pfAuth -match 'WPA3|WPA2' ? 'Green' : ($pfAuth -match 'WEP|Open' ? 'Red':'Yellow'))
        Write-Item "Profile Cipher" ($pfCipher ? $pfCipher : 'N/A') ($pfCipher -match 'CCMP|AES' ? 'Green' : ($pfCipher -match 'TKIP|WEP' ? 'Red':'Yellow'))
    } else {
        Write-Host "`nNo matching profile detected or SSID not present in profiles list." -ForegroundColor Yellow
    }

    # Quick recommendations
    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    if ($auth -and ($auth -match 'WPA3|WPA2')) {
        Write-Host "  - Security: Good (WPA2/WPA3)." -ForegroundColor Green
    } else {
        Write-Host "  - Security: Consider using WPA2/WPA3 and AES/CCMP cipher." -ForegroundColor Red
    }
    if ($dhcpEnabled) {
        Write-Host "  - DHCP: Enabled (default) - use static IP only when necessary." -ForegroundColor DarkYellow
    } else {
        Write-Host "  - DHCP: Disabled (static) - ensure DNS and gateway are correct." -ForegroundColor Green
    }

    Write-Host "`n--- End Adapter ---`n" -ForegroundColor DarkCyan
}
