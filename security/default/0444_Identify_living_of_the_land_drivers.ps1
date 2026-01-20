<#
.SYNOPSIS
    Identifies vulnerable "Living Off The Land" drivers on the local system.

.DESCRIPTION
    Downloads the LOLDrivers database from loldrivers.io and scans local driver files
    to identify any known vulnerable drivers by comparing SHA1 and SHA256 hashes.
    
    Based on the KQL query pattern for Microsoft Defender for Endpoint.

.NOTES
    Author: Security Script
    Source: https://www.loldrivers.io/
    Date: 2026-01-19

.EXAMPLE
    .\0444_Identify_living_of_the_land_drivers.ps1
    Scans the default driver location for vulnerable drivers.

.EXAMPLE
    .\0444_Identify_living_of_the_land_drivers.ps1 -IncludeAllDriverLocations -ExportCsv
    Scans all driver locations and exports results to CSV.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DriverPath = "$env:SystemRoot\System32\drivers",
    
    [Parameter()]
    [switch]$IncludeAllDriverLocations,
    
    [Parameter()]
    [string]$OutputPath,
    
    [Parameter()]
    [switch]$ExportCsv
)

# Configuration
$LOLDriversUrl = "https://www.loldrivers.io/api/drivers.json"
$script:VulnerableDriversFound = @()

function Write-Banner {
    $banner = @"
========================================================
   LOLDrivers - Vulnerable Driver Scanner  
   Identifies Living Off The Land Drivers on Your System
========================================================
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Get-LOLDriversDatabase {
    <#
    .SYNOPSIS
        Downloads and parses the LOLDrivers JSON database.
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "[*] Downloading LOLDrivers database from loldrivers.io..." -ForegroundColor Yellow
    
    try {
        # Download the JSON data using Invoke-WebRequest and manually parse
        $webResponse = Invoke-WebRequest -Uri $LOLDriversUrl -UseBasicParsing -ErrorAction Stop
        $response = $webResponse.Content | ConvertFrom-Json -AsHashtable
        
        Write-Host "[+] Successfully downloaded LOLDrivers database" -ForegroundColor Green
        Write-Host "[*] Processing driver entries..." -ForegroundColor Yellow
        
        # Parse and extract hash information
        $hashDatabase = @{
            SHA1 = @{}
            SHA256 = @{}
        }
        
        $totalDrivers = 0
        $totalSamples = 0
        
        foreach ($driver in $response) {
            $totalDrivers++
            $category = $driver.Category
            $verified = $driver.Verified
            
            # Process KnownVulnerableSamples (equivalent to mv-expand in KQL)
            if ($driver.KnownVulnerableSamples) {
                foreach ($sample in $driver.KnownVulnerableSamples) {
                    $totalSamples++
                    
                    $driverInfo = @{
                        Category = $category
                        Verified = $verified
                        MD5 = $sample.MD5
                        SHA1 = $sample.SHA1
                        SHA256 = $sample.SHA256
                        Filename = $sample.Filename
                        OriginalFilename = $sample.OriginalFilename
                        InternalName = $sample.InternalName
                        FileDescription = $sample.FileDescription
                        Product = $sample.Product
                        Company = $sample.Company
                        Publisher = $sample.Publisher
                    }
                    
                    # Add to SHA1 lookup table (if not empty)
                    if (-not [string]::IsNullOrWhiteSpace($sample.SHA1)) {
                        $sha1Upper = $sample.SHA1.ToUpper()
                        $hashDatabase.SHA1[$sha1Upper] = $driverInfo
                    }
                    
                    # Add to SHA256 lookup table (if not empty)
                    if (-not [string]::IsNullOrWhiteSpace($sample.SHA256)) {
                        $sha256Upper = $sample.SHA256.ToUpper()
                        $hashDatabase.SHA256[$sha256Upper] = $driverInfo
                    }
                }
            }
        }
        
        Write-Host "[+] Loaded $totalDrivers driver entries with $totalSamples vulnerable samples" -ForegroundColor Green
        Write-Host "[+] SHA256 hashes: $($hashDatabase.SHA256.Count) | SHA1 hashes: $($hashDatabase.SHA1.Count)" -ForegroundColor Green
        
        return $hashDatabase
    }
    catch {
        Write-Host "[!] Failed to download LOLDrivers database: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Get-FileHashSafe {
    <#
    .SYNOPSIS
        Safely computes file hashes, handling access denied errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [ValidateSet('SHA1', 'SHA256')]
        [string]$Algorithm
    )
    
    try {
        $hash = Get-FileHash -Path $Path -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash.ToUpper()
    }
    catch {
        Write-Verbose "Could not hash file $Path : $($_.Exception.Message)"
        return $null
    }
}

function Get-DriverLocations {
    <#
    .SYNOPSIS
        Gets all locations where driver files might be present.
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeAll
    )
    
    $locations = @(
        "$env:SystemRoot\System32\drivers"
    )
    
    if ($IncludeAll) {
        $locations += @(
            "$env:SystemRoot\System32\DriverStore\FileRepository"
            "$env:SystemRoot\INF"
            "$env:SystemRoot\SysWOW64\drivers"
        )
    }
    
    return $locations | Where-Object { Test-Path $_ }
}

function Find-VulnerableDrivers {
    <#
    .SYNOPSIS
        Scans local driver files and checks against LOLDrivers database.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$HashDatabase,
        
        [Parameter()]
        [string[]]$SearchPaths,
        
        [Parameter()]
        [switch]$IncludeAllLocations
    )
    
    if (-not $SearchPaths) {
        $SearchPaths = Get-DriverLocations -IncludeAll:$IncludeAllLocations
    }
    
    Write-Host ""
    Write-Host "[*] Scanning driver locations for vulnerable drivers..." -ForegroundColor Yellow
    
    $vulnerableDrivers = @()
    $scannedCount = 0
    $errorCount = 0
    
    foreach ($searchPath in $SearchPaths) {
        Write-Host "[*] Scanning: $searchPath" -ForegroundColor Cyan
        
        try {
            # Get all .sys files (driver files)
            $driverFiles = Get-ChildItem -Path $searchPath -Filter "*.sys" -Recurse -ErrorAction SilentlyContinue -File
            
            foreach ($file in $driverFiles) {
                $scannedCount++
                
                # Calculate SHA256 first (more common in the database)
                $sha256 = Get-FileHashSafe -Path $file.FullName -Algorithm SHA256
                
                # Display full path and hash for each file
                $hashDisplay = if ($sha256) { $sha256 } else { "N/A (access denied)" }
                Write-Host "    [$scannedCount] $($file.FullName)" -ForegroundColor Gray
                Write-Host "        SHA256: $hashDisplay" -ForegroundColor DarkGray
                
                $matchedInfo = $null
                $matchType = $null
                
                if ($sha256 -and $HashDatabase.SHA256.ContainsKey($sha256)) {
                    $matchedInfo = $HashDatabase.SHA256[$sha256]
                    $matchType = "SHA256"
                }
                else {
                    # If no SHA256 match, try SHA1
                    $sha1 = Get-FileHashSafe -Path $file.FullName -Algorithm SHA1
                    
                    if ($sha1 -and $HashDatabase.SHA1.ContainsKey($sha1)) {
                        $matchedInfo = $HashDatabase.SHA1[$sha1]
                        $matchType = "SHA1"
                    }
                }
                
                if ($matchedInfo) {
                    $vulnerableDriver = [PSCustomObject]@{
                        LocalPath = $file.FullName
                        FileName = $file.Name
                        FileSize = $file.Length
                        LastModified = $file.LastWriteTime
                        MatchType = $matchType
                        SHA256 = $sha256
                        SHA1 = if ($matchType -eq "SHA1") { $sha1 } else { $null }
                        Category = $matchedInfo.Category
                        Verified = $matchedInfo.Verified
                        KnownFilename = $matchedInfo.Filename
                        OriginalFilename = $matchedInfo.OriginalFilename
                        FileDescription = $matchedInfo.FileDescription
                        Product = $matchedInfo.Product
                        Company = $matchedInfo.Company
                        Publisher = $matchedInfo.Publisher
                    }
                    
                    $vulnerableDrivers += $vulnerableDriver
                    
                    # Alert immediately when found
                    Write-Host ""
                    Write-Host "[!] VULNERABLE DRIVER FOUND!" -ForegroundColor Red -BackgroundColor Yellow
                    Write-Host "    Path: $($file.FullName)" -ForegroundColor Red
                    Write-Host "    Category: $($matchedInfo.Category)" -ForegroundColor Red
                    Write-Host "    Description: $($matchedInfo.FileDescription)" -ForegroundColor Red
                    Write-Host "    Match Type: $matchType" -ForegroundColor Red
                    Write-Host ""
                }
            }
        }
        catch {
            $errorCount++
            Write-Verbose "Error scanning $searchPath : $($_.Exception.Message)"
        }
    }
    
    Write-Host ""
    Write-Host "[*] Scan complete: $scannedCount files scanned" -ForegroundColor Green
    
    return $vulnerableDrivers
}

function Show-Results {
    <#
    .SYNOPSIS
        Displays the scan results in a formatted table.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [array]$VulnerableDrivers
    )
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                    SCAN RESULTS                        " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not $VulnerableDrivers -or $VulnerableDrivers.Count -eq 0) {
        Write-Host "[+] No vulnerable drivers detected on this system." -ForegroundColor Green
        Write-Host ""
        return
    }
    
    Write-Host "[!] Found $($VulnerableDrivers.Count) vulnerable driver(s)!" -ForegroundColor Red
    Write-Host ""
    
    foreach ($driver in $VulnerableDrivers) {
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " VULNERABLE DRIVER" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " Local Path:    $($driver.LocalPath)" -ForegroundColor White
        Write-Host " File Name:     $($driver.FileName)" -ForegroundColor White
        Write-Host " File Size:     $($driver.FileSize) bytes" -ForegroundColor White
        Write-Host " Last Modified: $($driver.LastModified)" -ForegroundColor White
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " Category:      $($driver.Category)" -ForegroundColor Red
        Write-Host " Verified:      $($driver.Verified)" -ForegroundColor White
        Write-Host " Description:   $($driver.FileDescription)" -ForegroundColor White
        Write-Host " Product:       $($driver.Product)" -ForegroundColor White
        Write-Host " Company:       $($driver.Company)" -ForegroundColor White
        Write-Host " Publisher:     $($driver.Publisher)" -ForegroundColor White
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " Match Type:    $($driver.MatchType)" -ForegroundColor Cyan
        Write-Host " SHA256:        $($driver.SHA256)" -ForegroundColor Gray
        if ($driver.SHA1) {
            Write-Host " SHA1:          $($driver.SHA1)" -ForegroundColor Gray
        }
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Summary by category
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                  SUMMARY BY CATEGORY                   " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    
    $VulnerableDrivers | Group-Object -Property Category | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count) driver(s)" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Export-Results {
    <#
    .SYNOPSIS
        Exports scan results to a CSV file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$VulnerableDrivers,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    try {
        $VulnerableDrivers | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Results exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to export results: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
function Main {
    Write-Banner
    
    # Check if running as administrator (recommended for full access to driver files)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] Warning: Running without administrator privileges." -ForegroundColor Yellow
        Write-Host "    Some driver files may not be accessible." -ForegroundColor Yellow
        Write-Host "    Consider running as Administrator for complete scanning." -ForegroundColor Yellow
        Write-Host ""
    }
    
    try {
        # Download and parse LOLDrivers database
        $hashDatabase = Get-LOLDriversDatabase
        
        # Determine search paths
        $searchPaths = if ($DriverPath -and (Test-Path $DriverPath)) {
            @($DriverPath)
        } else {
            Get-DriverLocations -IncludeAll:$IncludeAllDriverLocations
        }
        
        # Scan for vulnerable drivers
        $vulnerableDrivers = Find-VulnerableDrivers -HashDatabase $hashDatabase -SearchPaths $searchPaths -IncludeAllLocations:$IncludeAllDriverLocations
        
        # Display results
        Show-Results -VulnerableDrivers $vulnerableDrivers
        
        # Export if requested
        if ($ExportCsv -and $vulnerableDrivers -and $vulnerableDrivers.Count -gt 0) {
            $exportPath = if ($OutputPath) { 
                $OutputPath 
            } else { 
                Join-Path -Path $PWD -ChildPath "LOLDrivers_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
            Export-Results -VulnerableDrivers $vulnerableDrivers -OutputPath $exportPath
        }
        
        # Return results for programmatic use
        return $vulnerableDrivers
    }
    catch {
        Write-Host "[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Run the script
$results = Main

# Output object for pipeline usage
if ($results) {
    Write-Output $results
}
