<#
.SYNOPSIS
    Identifies "Living Off The Land" Remote Monitoring and Management (RMM) tools on the local system.

.DESCRIPTION
    Downloads the LOLRMM database from lolrmm.io and scans the local system for 
    RMM tools that could potentially be abused by threat actors.
    
    The script checks for:
    - Installation paths
    - Specific file artifacts on disk
    - Registry keys
    - Service names

.NOTES
    Author: Security Script
    Source: https://lolrmm.io/
    Date: 2026-01-19

.EXAMPLE
    .\0445_Identify_living_of_the_land_remote_monitoring_management.ps1
    Scans the system for RMM tools using default settings.

.EXAMPLE
    .\0445_Identify_living_of_the_land_remote_monitoring_management.ps1 -ExportCsv
    Scans the system and exports any findings to a CSV file.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath,
    
    [Parameter()]
    [switch]$ExportCsv,

    [Parameter()]
    [switch]$DetailedScan
)

# Configuration
$LOLRMMUrl = "https://lolrmm.io/api/rmm_tools.json"
$script:Findings = @()

function Write-Banner {
    $banner = @"
========================================================
    LOLRMM - Remote Monitoring & Management Scanner
  Identifies Potentially Abused RMM Tools on Your System
========================================================
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Get-LOLRMMDatabase {
    <#
    .SYNOPSIS
        Downloads and parses the LOLRMM JSON database.
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "[*] Downloading LOLRMM database from lolrmm.io..." -ForegroundColor Yellow
    
    try {
        $webResponse = Invoke-WebRequest -Uri $LOLRMMUrl -UseBasicParsing -ErrorAction Stop
        $response = $webResponse.Content | ConvertFrom-Json -AsHashtable
        
        Write-Host "[+] Successfully downloaded LOLRMM database" -ForegroundColor Green
        Write-Host "[*] Loaded $(@($response).Count) RMM tool entries" -ForegroundColor Green
        
        return $response
    }
    catch {
        Write-Host "[!] Failed to download LOLRMM database: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Expand-EnvVars {
    <#
    .SYNOPSIS
        Expands environment variables and handles wildcards in paths.
    #>
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    # Replace %VAR% with $env:VAR
    $expanded = [System.Environment]::ExpandEnvironmentVariables($Path)
    
    # Handle ~/ as home directory
    if ($expanded -like "~/*") {
        $expanded = $expanded -replace "^~", $env:USERPROFILE
    }

    return $expanded
}

function Test-PathSafe {
    param([string]$Path)
    try {
        return Test-Path -Path $Path -ErrorAction SilentlyContinue
    }
    catch {
        return $false
    }
}

function Get-PathMetadata {
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $sizeBytes = if ($item.PSIsContainer) { $null } else { [int64]$item.Length }
        return [PSCustomObject]@{
            ItemType      = if ($item.PSIsContainer) { "Directory" } else { "File" }
            SizeBytes     = $sizeBytes
            CreationTime  = $item.CreationTime
            LastWriteTime = $item.LastWriteTime
        }
    } catch {
        return $null
    }
}

function Get-FileSha256Safe {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    } catch {
        return $null
    }
}

function Find-RMMTools {
    <#
    .SYNOPSIS
        Scans the local system for RMM tool artifacts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Database
    )
    
    $foundTools = @()
    $totalTools = $Database.Count
    $currentIndex = 0

    Write-Host ""
    Write-Host "[*] Scanning system for RMM artifacts..." -ForegroundColor Yellow

    foreach ($tool in $Database) {
        $currentIndex++
        $toolName = $tool.Name
        $detectedArtifacts = @()
        
        # 1. Check Installation Paths
        if ($tool.Details -and $tool.Details.InstallationPaths) {
            foreach ($pathTemplate in $tool.Details.InstallationPaths) {
                if ($pathTemplate -like "/*") { continue } # Skip non-Windows paths
                
                $expandedPath = Expand-EnvVars $pathTemplate
                if ($expandedPath) {
                    Write-Host "    [$currentIndex/$totalTools] Checking Path: $expandedPath" -ForegroundColor Gray
                    if (Test-PathSafe $expandedPath) {
                        $meta = Get-PathMetadata -Path $expandedPath
                        $sha256 = Get-FileSha256Safe -Path $expandedPath
                        $detectedArtifacts += [PSCustomObject]@{
                            Type = "InstallationPath"
                            Value = $expandedPath
                            Original = $pathTemplate
                            SHA256 = $sha256
                            ItemType = if ($meta) { $meta.ItemType } else { $null }
                            SizeBytes = if ($meta) { $meta.SizeBytes } else { $null }
                            CreationTime = if ($meta) { $meta.CreationTime } else { $null }
                            LastWriteTime = if ($meta) { $meta.LastWriteTime } else { $null }
                        }
                    }
                }
            }
        }

        # 2. Check Disk Artifacts
        if ($tool.Artifacts -and $tool.Artifacts.Disk) {
            foreach ($artifact in $tool.Artifacts.Disk) {
                if ($artifact.File) {
                    if ($artifact.File -like "/*" -or $artifact.File -like "~/*") { continue } # Skip non-Windows paths
                    
                    $expandedFile = Expand-EnvVars $artifact.File
                    if ($expandedFile) {
                        Write-Host "    [$currentIndex/$totalTools] Checking File: $expandedFile" -ForegroundColor Gray
                        if (Test-PathSafe $expandedFile) {
                            $meta = Get-PathMetadata -Path $expandedFile
                            # Calculate hash for found files to match "full path and hash" requirement
                            $sha256 = Get-FileSha256Safe -Path $expandedFile
                            if ($sha256) { Write-Host "        SHA256: $sha256" -ForegroundColor DarkGray }

                            $detectedArtifacts += [PSCustomObject]@{
                                Type = "FileArtifact"
                                Value = $expandedFile
                                Original = $artifact.File
                                Description = $artifact.Description
                                SHA256 = $sha256
                                ItemType = if ($meta) { $meta.ItemType } else { $null }
                                SizeBytes = if ($meta) { $meta.SizeBytes } else { $null }
                                CreationTime = if ($meta) { $meta.CreationTime } else { $null }
                                LastWriteTime = if ($meta) { $meta.LastWriteTime } else { $null }
                            }
                        }
                    }
                }
            }
        }

        # 3. Check Registry Artifacts
        if ($tool.Artifacts -and $tool.Artifacts.Registry) {
            foreach ($reg in $tool.Artifacts.Registry) {
                if ($reg.Path) {
                    Write-Host "    [$currentIndex/$totalTools] Checking Registry: $($reg.Path)" -ForegroundColor Gray
                    # Convert HKLM, HKCU, etc. for Test-Path
                    $regPath = $reg.Path -replace '^HKLM\\', 'HLM:\' -replace '^HKCU\\', 'HKCU:\'
                    if (Test-PathSafe $regPath) {
                        $detectedArtifacts += [PSCustomObject]@{
                            Type = "RegistryArtifact"
                            Value = $reg.Path
                            Description = $reg.Description
                        }
                    }
                }
            }
        }

        # 4. Check Services
        if ($tool.Artifacts -and $tool.Artifacts.EventLog) {
            foreach ($event in $tool.Artifacts.EventLog) {
                if ($event.ServiceName) {
                    Write-Host "    [$currentIndex/$totalTools] Checking Service: $($event.ServiceName)" -ForegroundColor Gray
                    $svc = Get-Service -Name $event.ServiceName -ErrorAction SilentlyContinue
                    if ($svc) {
                        $detectedArtifacts += [PSCustomObject]@{
                            Type = "Service"
                            Value = $event.ServiceName
                            Description = $event.Description
                        }
                    }
                }
            }
        }

        if ($detectedArtifacts.Count -gt 0) {
            $toolFinding = [PSCustomObject]@{
                ToolName    = $toolName
                Category    = $tool.Category
                Description = $tool.Description
                Artifacts   = $detectedArtifacts
            }
            $foundTools += $toolFinding

            # Alert immediately
            Write-Host ""
            Write-Host "[!] RMM TOOL DETECTED: $toolName" -ForegroundColor Red -BackgroundColor Yellow
            Write-Host "    Category: $($tool.Category)" -ForegroundColor Red
            foreach ($art in $detectedArtifacts) {
                Write-Host "    - Found $($art.Type): $($art.Value)" -ForegroundColor Red
            }
            Write-Host ""
        }
    }

    Write-Host "[*] Scan complete." -ForegroundColor Green
    return $foundTools
}

function Show-Results {
    param(
        [array]$Findings
    )

    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                    SCAN RESULTS                        " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Host "[+] No RMM tools from the LOLRMM list were detected." -ForegroundColor Green
        Write-Host ""
        return
    }

    Write-Host "[!] Found $($Findings.Count) RMM tool(s)!" -ForegroundColor Red
    Write-Host ""

    foreach ($finding in $Findings) {
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " RMM TOOL DETECTED: $($finding.ToolName)" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " Category:      $($finding.Category)" -ForegroundColor White
        Write-Host " Description:   $($finding.Description)" -ForegroundColor Gray -NoNewline
        Write-Host ""
        Write-Host " Detected Artifacts:" -ForegroundColor Cyan
        foreach ($art in $finding.Artifacts) {
            Write-Host "  [$($art.Type)] $($art.Value)" -ForegroundColor White
            if ($art.PSObject.Properties.Match('CreationTime').Count -gt 0 -and $art.CreationTime) {
                Write-Host "    Created: $($art.CreationTime)" -ForegroundColor Gray
            }
            if ($art.PSObject.Properties.Match('LastWriteTime').Count -gt 0 -and $art.LastWriteTime) {
                Write-Host "    Modified: $($art.LastWriteTime)" -ForegroundColor Gray
            }
            if ($art.PSObject.Properties.Match('SizeBytes').Count -gt 0 -and $null -ne $art.SizeBytes) {
                Write-Host "    Size: $($art.SizeBytes) bytes" -ForegroundColor Gray
            }
            if ($art.PSObject.Properties.Match('SHA256').Count -gt 0 -and $art.SHA256) {
                Write-Host "    SHA-256: $($art.SHA256)" -ForegroundColor Gray
            }
            if ($art.Description -and $art.Description -ne "N/A") {
                Write-Host "    Detail: $($art.Description)" -ForegroundColor Gray
            }
        }
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host ""
    }
}

function Export-Results {
    param(
        [array]$Findings,
        [string]$Path
    )

    try {
        # Flatten findings for CSV
        $flattened = foreach ($f in $Findings) {
            foreach ($a in $f.Artifacts) {
                [PSCustomObject]@{
                    ToolName     = $f.ToolName
                    Category     = $f.Category
                    ArtifactType = $a.Type
                    ArtifactValue = $a.Value
                    Description   = $a.Description
                    SHA256        = $a.SHA256
                    ItemType      = $a.ItemType
                    SizeBytes     = $a.SizeBytes
                    CreationTime  = $a.CreationTime
                    LastWriteTime = $a.LastWriteTime
                }
            }
        }
        $flattened | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Results exported to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to export results: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Main {
    Write-Banner
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] Warning: Running without administrator privileges." -ForegroundColor Yellow
        Write-Host "    Some registry keys or files may not be accessible." -ForegroundColor Yellow
        Write-Host ""
    }

    try {
        $db = Get-LOLRMMDatabase
        $findings = Find-RMMTools -Database $db
        Show-Results -Findings $findings

        if ($ExportCsv -and $findings.Count -gt 0) {
            $exportPath = if ($OutputPath) { $OutputPath } else { Join-Path -Path $PWD -ChildPath "LOLRMM_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
            Export-Results -Findings $findings -Path $exportPath
        }

        return $findings
    }
    catch {
        Write-Host "[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

$results = Main
if ($results) { Write-Output $results }
