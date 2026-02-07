<#
.SYNOPSIS
    Chrysalis / Lotus Blossom hunting script (host & basic network artifacts)
                based on ompromise of the infrastructure hosting Notepad++

.DESCRIPTION
    - Looks for key Chrysalis / loader files by hash and filename.
    - Hunts for characteristic directories and persistence.
    - Checks for the Chrysalis mutex.
    - Looks for known C2 hostnames / IPs in recent DNS cache and firewall logs (optional).
    - Outputs suspicious artifacts as PowerShell objects for pipeline use.

    All IOCs and behaviors are taken from Rapid7:
    "The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's Toolkit"
    https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
#>

[CmdletBinding()]
param(
    [string[]] $SearchRoots = @("C:\ProgramData", "$env:APPDATA", "$env:LOCALAPPDATA"),
    [switch]   $DeepDiskScan,          # If set, adds C:\Users and C:\ to scan roots (heavy)
    [bool]     $CheckDnsCache = $true,
    [bool]     $CheckFirewallLogs = $true,
    [string]   $FirewallLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

# --- Progress & Debug Helper Functions --------------------------------------

$script:StartTime = Get-Date
$script:TotalSteps = 5
$script:CurrentStep = 0

function Write-ProgressBanner {
    param([string]$Message, [int]$Step, [int]$Total)
    $percent = [math]::Round(($Step / $Total) * 100)
    $barLength = 40
    $filled = [math]::Round($barLength * $Step / $Total)
    $empty = $barLength - $filled
    $bar = ("█" * $filled) + ("░" * $empty)
    Write-Host "`n[$bar] $percent% - Step $Step/$Total" -ForegroundColor Cyan
    Write-Host "► $Message" -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor DarkGray
}

function Write-Debug-Info {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = (Get-Date).ToString("HH:mm:ss.fff")
    $color = switch ($Level) {
        "INFO"    { "Gray" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "DEBUG"   { "DarkCyan" }
        default   { "White" }
    }
    Write-Host "  [$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Write-ScanProgress {
    param([string]$Item, [int]$Current, [int]$Total)
    if ($Total -gt 0) {
        $pct = [math]::Round(($Current / $Total) * 100)
        Write-Progress -Activity "Scanning for Chrysalis IoCs" -Status "$Item" -PercentComplete $pct
    }
}

# --- Script Banner ----------------------------------------------------------

Write-Host "`n" -NoNewline
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║       CHRYSALIS / LOTUS BLOSSOM DETECTION SCRIPT               ║" -ForegroundColor Magenta
Write-Host "║       IOCs sourced from Rapid7 Threat Analysis                 ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host "`nStarted at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "Deep Scan: $DeepDiskScan | DNS Cache Check: $CheckDnsCache | Firewall Log Check: $CheckFirewallLogs" -ForegroundColor DarkGray
Write-Host ""

# --- IOC definitions --------------------------------------------------------

# File hashes (SHA-256) and expected names from Rapid7 IoC table[page:0]
$FileIoCs = @(
    @{ Name = "update.exe";             Sha256 = "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9" },
    @{ Name = "[NSIS].nsi";             Sha256 = "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e" },
    @{ Name = "BluetoothService.exe";   Sha256 = "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924" },
    @{ Name = "BluetoothService";       Sha256 = "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e" },
    @{ Name = "log.dll";                Sha256 = "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad" },
    @{ Name = "u.bat";                  Sha256 = "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600" },
    @{ Name = "conf.c";                 Sha256 = "f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a" },
    @{ Name = "libtcc.dll";             Sha256 = "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906" },
    @{ Name = "admin";                  Sha256 = "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd" },
    @{ Name = "loader1";                Sha256 = "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd" },
    @{ Name = "uffhxpSy";               Sha256 = "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8" },
    @{ Name = "loader2";                Sha256 = "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda" },
    @{ Name = "3yzr31vk";               Sha256 = "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5" },
    @{ Name = "ConsoleApplication2.exe";Sha256 = "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3" },
    @{ Name = "system";                 Sha256 = "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd" },
    @{ Name = "s047t5g.exe";            Sha256 = "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a" }
)

# Network IoCs from Rapid7[page:0]
$NetworkIoCs = @{
    Domains = @(
        "api.skycloudcenter.com",
        "api.wiresguard.com"
    )
    Ips = @(
        "95.179.213.0",
        "61.4.102.97",
        "59.110.7.32",
        "124.222.137.114"
    )
}

# Known folder / file locations from the article[page:0]
$SuspiciousPaths = @(
    "$env:APPDATA\Bluetooth",                  # HIDDEN Bluetooth folder with BluetoothService.exe etc.                   
    "C:\ProgramData\USOShared\svchost.exe",# USOShared folder containing renamed TinyCC (svchost.exe) & conf.c
    "C:\ProgramData\USOShared\conf.c",
    "C:\ProgramData\USOShared\libtcc.dll"
)

# Mutex used by Chrysalis[page:0]
$ChrysalisMutex = "Global\Jdhfv_1.0.1"

# Known C2 URL fragment used in config (Deepseek-like path)[page:0]
$C2PathFragment = "/a/chat/s/"

# --- Helper: SHA-256 hashing -----------------------------------------------

function Get-FileSha256 {
    param(
        [Parameter(Mandatory=$true)]
        [string] $Path
    )
    try {
        if (Test-Path -LiteralPath $Path) {
            $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
            return $hash.Hash.ToLowerInvariant()
        }
    } catch {
        return $null
    }
}

# --- Scan for file-based IoCs ----------------------------------------------

function Find-ChrysalisFiles {
    param(
        [string[]] $Roots
    )

    $patterns = $FileIoCs.Name | Select-Object -Unique
    Write-Debug-Info "Looking for $($patterns.Count) unique filename patterns" "DEBUG"
    
    $rootIndex = 0
    $totalRoots = $Roots.Count
    
    foreach ($root in $Roots) {
        $rootIndex++
        if (-not (Test-Path -LiteralPath $root)) { 
            Write-Debug-Info "Skipping non-existent path: $root" "WARNING"
            continue 
        }
        
        Write-Debug-Info "Scanning root [$rootIndex/$totalRoots]: $root" "INFO"
        $fileCount = 0

        Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue -Force |
            Where-Object { -not $_.PSIsContainer -and ($patterns -contains $_.Name) } |
            ForEach-Object {
                $file = $_
                $fileCount++
                Write-Debug-Info "Checking suspicious filename: $($file.Name) at $($file.DirectoryName)" "DEBUG"
                $hash = Get-FileSha256 -Path $file.FullName
                if (-not $hash) { return }

                $match = $FileIoCs | Where-Object { $_.Name -eq $file.Name -and $_.Sha256 -eq $hash }
                if ($match) {
                    Write-Debug-Info "[!] MATCH FOUND: $($file.FullName)" "WARNING"
                    [PSCustomObject]@{
                        Type        = "FileIoC"
                        Name        = $file.Name
                        Path        = $file.FullName
                        Sha256      = $hash
                        MatchedSha  = $true
                        Description = "Chrysalis / loader IoC match (name + SHA256 from Rapid7)"
                    }
                }
            }
        Write-Debug-Info "Checked $fileCount potential matches in $root" "INFO"
    }
}

# --- Scan for suspicious folders / files -----------------------------------

function Find-ChrysalisPaths {
    Write-Debug-Info "Checking $($SuspiciousPaths.Count) known suspicious paths" "DEBUG"
    $checkedCount = 0
    $foundCount = 0
    
    foreach ($p in $SuspiciousPaths) {
        $checkedCount++
        Write-ScanProgress -Item "Checking: $p" -Current $checkedCount -Total $SuspiciousPaths.Count
        
        if (Test-Path -LiteralPath $p) {
            $foundCount++
            Write-Debug-Info "[!] Suspicious path EXISTS: $p" "WARNING"
            $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Type        = "SuspiciousPath"
                Path        = $p
                Exists      = $true
                Description = "Path observed in Chrysalis intrusion chain (USOShared / Bluetooth)."
            }
        } else {
            Write-Debug-Info "Path not found (OK): $p" "DEBUG"
        }
    }
    Write-Debug-Info "Path check complete: $foundCount/$checkedCount suspicious paths found" "INFO"
}

# --- Mutex check via running processes -------------------------------------

function Test-ChrysalisMutex {
    param(
        [string] $MutexName
    )

    Write-Debug-Info "Testing for Chrysalis mutex: $MutexName" "DEBUG"

    # We enumerate processes and .NET mutexes in-process.
    # This is heuristic – on a live infected system the mutex may already exist.[page:0]
    try {
        # Try to open the mutex (will throw if it does not exist)
        $createdNew = $false
        $m = New-Object System.Threading.Mutex($true, $MutexName, [ref]$createdNew)
        if ($m -and -not $createdNew) {
            # Mutex already existed
            Write-Debug-Info "[!] CRITICAL: Chrysalis mutex DETECTED!" "ERROR"
            $m.ReleaseMutex() | Out-Null
            [PSCustomObject]@{
                Type        = "Mutex"
                Name        = $MutexName
                Exists      = $true
                Description = "Chrysalis mutex present (may indicate active / recent infection)."
            }
        } else {
            # We created it, so original did not exist
            Write-Debug-Info "Mutex not present (OK)" "SUCCESS"
            if ($m) { $m.ReleaseMutex() | Out-Null }
        }
    } catch {
        Write-Debug-Info "Mutex check failed: $($_.Exception.Message)" "WARNING"
        # If OpenExisting succeeds but NewObject fails, we still treat as suspicious.
    }
}

# --- DNS cache hunting for C2 domains --------------------------------------

function Find-ChrysalisDnsCache {
    $results = @()
    Write-Debug-Info "Retrieving DNS cache entries..." "DEBUG"
    try {
        $lines = ipconfig /displaydns 2>$null
        $lineCount = ($lines | Measure-Object).Count
        Write-Debug-Info "Retrieved $lineCount lines from DNS cache" "INFO"
        
        foreach ($domain in $NetworkIoCs.Domains) {
            Write-Debug-Info "Searching for C2 domain: $domain" "DEBUG"
            $pattern = [Regex]::Escape($domain)
            if ($lines -match $pattern) {
                Write-Debug-Info "[!] C2 domain found in DNS cache: $domain" "ERROR"
                $results += [PSCustomObject]@{
                    Type        = "DnsCache"
                    Indicator   = $domain
                    Description = "Chrysalis C2 domain seen in local DNS cache."
                }
            }
        }
        if ($results.Count -eq 0) {
            Write-Debug-Info "No C2 domains found in DNS cache (OK)" "SUCCESS"
        }
    } catch {
        Write-Debug-Info "DNS cache check failed: $($_.Exception.Message)" "WARNING"
    }
    $results
}

# --- Firewall log hunting for C2 IPs / domains -----------------------------

function Find-ChrysalisFirewallLogs {
    param(
        [string] $LogPath
    )

    Write-Debug-Info "Checking firewall log: $LogPath" "DEBUG"

    if (-not (Test-Path -LiteralPath $LogPath)) { 
        Write-Debug-Info "Firewall log not found at: $LogPath" "WARNING"
        return 
    }

    $results = @()
    $lineNumber = 0

    try {
        $logLines = Get-Content -LiteralPath $LogPath -ErrorAction Stop
        $totalLines = $logLines.Count
        Write-Debug-Info "Analyzing $totalLines firewall log entries..." "INFO"
        
        $logLines | ForEach-Object {
            $line = $_
            $lineNumber++
            
            # Update progress every 1000 lines
            if ($lineNumber % 1000 -eq 0) {
                Write-ScanProgress -Item "Firewall log line $lineNumber/$totalLines" -Current $lineNumber -Total $totalLines
            }
            
            foreach ($ip in $NetworkIoCs.Ips) {
                if ($line -match [Regex]::Escape($ip)) {
                    Write-Debug-Info "[!] C2 IP found in firewall log (line $lineNumber): $ip" "ERROR"
                    $results += [PSCustomObject]@{
                        Type        = "Firewall"
                        Indicator   = $ip
                        Line        = $line
                        Description = "Connection involving Chrysalis-related IP seen in firewall log."
                    }
                }
            }

            foreach ($domain in $NetworkIoCs.Domains) {
                if ($line -match [Regex]::Escape($domain)) {
                    Write-Debug-Info "[!] C2 domain found in firewall log (line $lineNumber): $domain" "ERROR"
                    $results += [PSCustomObject]@{
                        Type        = "Firewall"
                        Indicator   = $domain
                        Line        = $line
                        Description = "Connection involving Chrysalis-related domain seen in firewall log."
                    }
                }
            }
        }
        Write-Debug-Info "Firewall log analysis complete: $($results.Count) IoC matches" "INFO"
    } catch {
        Write-Debug-Info "Firewall log check failed: $($_.Exception.Message)" "WARNING"
    }

    $results
}

# --- Main -------------------------------------------------------------------

if ($DeepDiskScan) {
    Write-Debug-Info "Deep scan enabled - adding C:\Users and C:\ to search roots" "INFO"
    $SearchRoots += @("C:\Users", "C:\")
}

Write-Debug-Info "Search roots: $($SearchRoots -join ', ')" "INFO"

$allFindings = @()

# 1) File-based IoCs (hash + filename)[page:0]
$script:CurrentStep = 1
Write-ProgressBanner -Message "Scanning for Chrysalis file IoCs (hash + filename matching)" -Step $script:CurrentStep -Total $script:TotalSteps
$allFindings += Find-ChrysalisFiles -Roots $SearchRoots
Write-Debug-Info "File scan complete. Findings so far: $($allFindings.Count)" "SUCCESS"

# 2) Known suspicious folders / files[page:0]
$script:CurrentStep = 2
Write-ProgressBanner -Message "Checking known suspicious paths (USOShared, Bluetooth folders)" -Step $script:CurrentStep -Total $script:TotalSteps
$allFindings += Find-ChrysalisPaths
Write-Debug-Info "Path check complete. Findings so far: $($allFindings.Count)" "SUCCESS"

# 3) Mutex presence[page:0]
$script:CurrentStep = 3
Write-ProgressBanner -Message "Testing for Chrysalis mutex (active infection indicator)" -Step $script:CurrentStep -Total $script:TotalSteps
$mutexFinding = Test-ChrysalisMutex -MutexName $ChrysalisMutex
if ($mutexFinding) { $allFindings += $mutexFinding }
Write-Debug-Info "Mutex check complete. Findings so far: $($allFindings.Count)" "SUCCESS"

# 4) DNS cache for C2 domains[page:0]
$script:CurrentStep = 4
if ($CheckDnsCache) {
    Write-ProgressBanner -Message "Hunting C2 domains in DNS cache" -Step $script:CurrentStep -Total $script:TotalSteps
    $allFindings += Find-ChrysalisDnsCache
    Write-Debug-Info "DNS cache check complete. Findings so far: $($allFindings.Count)" "SUCCESS"
} else {
    Write-ProgressBanner -Message "DNS cache check SKIPPED (use -CheckDnsCache to enable)" -Step $script:CurrentStep -Total $script:TotalSteps
    Write-Debug-Info "DNS cache check skipped" "INFO"
}

# 5) Firewall logs for C2 indicators[page:0]
$script:CurrentStep = 5
if ($CheckFirewallLogs) {
    Write-ProgressBanner -Message "Scanning firewall logs for C2 indicators" -Step $script:CurrentStep -Total $script:TotalSteps
    $allFindings += Find-ChrysalisFirewallLogs -LogPath $FirewallLogPath
    Write-Debug-Info "Firewall log check complete. Findings so far: $($allFindings.Count)" "SUCCESS"
} else {
    Write-ProgressBanner -Message "Firewall log check SKIPPED (use -CheckFirewallLogs to enable)" -Step $script:CurrentStep -Total $script:TotalSteps
    Write-Debug-Info "Firewall log check skipped" "INFO"
}

# Clear progress bar
Write-Progress -Activity "Scanning for Chrysalis IoCs" -Completed

# --- Summary ----------------------------------------------------------------

$endTime = Get-Date
$duration = $endTime - $script:StartTime

Write-Host "`n" -NoNewline
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║                        SCAN COMPLETE                           ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host "Duration: $($duration.ToString('mm\:ss\.fff'))" -ForegroundColor DarkGray
Write-Host "Completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host ""

if ($allFindings.Count -eq 0) {
    Write-Host "✓ No Chrysalis-related IoCs detected." -ForegroundColor Green
    Write-Host "  System appears clean based on current heuristics and paths." -ForegroundColor Gray
} else {
    Write-Host "⚠ WARNING: $($allFindings.Count) potential IoC(s) detected!" -ForegroundColor Red
    Write-Host "  Review findings below:" -ForegroundColor Yellow
    Write-Host ""
    $allFindings
}
