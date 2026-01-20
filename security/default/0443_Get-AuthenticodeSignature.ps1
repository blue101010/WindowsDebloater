#
# .SYNOPSIS
#   Validates digital signatures (Authenticode) of executables in Windows system directories
#   to detect unsigned, tampered, or potentially malicious binaries.
#
# .DESCRIPTION
#   This security script scans executables (.exe files) in critical Windows directories
#   (SystemApps and WinSxS) and verifies their Authenticode digital signatures using
#   the Get-AuthenticodeSignature cmdlet.
#
#   Key capabilities:
#     - Identifies unsigned or improperly signed executables that may indicate tampering
#     - Displays signer certificate details (Subject, Thumbprint) for verification
#     - Generates JSON baselines of valid/invalid executables for change detection
#     - Supports both interactive menu and batch/automation modes
#
#   Scan modes (batch switches):
#     --batch show-exec-invalid   List executables with non-Valid signature status (option A)
#     --batch show-exec-details   List all executables with full certificate details (option B)
#     --batch show-searchhost     Focus on SearchHost.exe instances only (option C)
#     --batch show-exec-valid     List Valid executables and save baseline (option D)
#     --prompt                    Show interactive menu after batch run
#
#   Baseline outputs (for drift detection and auditing):
#     * Option A: baselines/0443-AuthenticodeSignature-invalid-baseline-yyyy-MM-dd-HH-mm.json
#     * Option D: baselines/0443-AuthenticodeSignature-valid-baseline-yyyy-MM-dd-HH-mm.json
#     * Override paths with -InvalidBaselinePath / -BaselinePath or skip via -NoBaseline
#
# .NOTES
#   Requires administrative permissions to access certain WinSxS subdirectories.
#   Run from an elevated PowerShell session for best coverage.
#

param(
    [Alias('batch')]
    [ValidateSet('menu','show-exec-invalid','show-exec-details','show-searchhost','show-exec-valid')]
    [string]$Mode = 'menu',

    [Alias('prompt')]
    [switch]$ShowMenuAfterBatch,

    [switch]$Help,

    [string]$BaselinePath = 'baselines/0443-AuthenticodeSignature-valid-baseline-yyyy-MM-dd-HH-mm.json',
    [string]$InvalidBaselinePath = 'baselines/0443-AuthenticodeSignature-invalid-baseline-yyyy-MM-dd-HH-mm.json',

    [switch]$NoBaseline
)

$script:AllExeResults = $null
$script:SearchHostResults = $null
$script:ShouldPause = $true
$script:TrustProviderWarning = 'The form specified for the subject is not one supported or known by the specified trust provider.'

if ($Help) {
    Show-AuthenticodeUsage
    return
}

$paths = @(
    'C:\Windows\SystemApps',
    'C:\Windows\WinSxS'
)

function Format-SignerCertificate {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Certificate) {
        return '<none>'
    }

    return "{0} | Thumbprint: {1}" -f $Certificate.Subject, $Certificate.Thumbprint
}

function Show-AuthenticodeUsage {
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  Interactive menu (default):" -NoNewline; Write-Host "  pwsh .\0443_Get-AuthenticodeSignature.ps1" -ForegroundColor Gray
    Write-Host "  Batch options:" -NoNewline; Write-Host "     pwsh .\0443_Get-AuthenticodeSignature.ps1 -Mode <option>" -ForegroundColor Gray
    Write-Host "    Options:" -ForegroundColor Gray
    Write-Host "      show-exec-invalid  -> same as menu option A" -ForegroundColor Gray
    Write-Host "      show-exec-details  -> same as option B" -ForegroundColor Gray
    Write-Host "      show-searchhost    -> same as option C" -ForegroundColor Gray
    Write-Host "      show-exec-valid    -> same as option D (valid executables + baseline)" -ForegroundColor Gray
    Write-Host "    Add -Prompt to drop into the interactive menu after a batch run." -ForegroundColor Gray
    Write-Host "    Baseline switches (Options A & D):" -ForegroundColor Gray
    Write-Host "      -InvalidBaselinePath <file> defaults to baselines/0443-AuthenticodeSignature-invalid-baseline-yyyy-MM-dd-HH-mm.json" -ForegroundColor Gray
    Write-Host "      -BaselinePath <file>         defaults to baselines/0443-AuthenticodeSignature-valid-baseline-yyyy-MM-dd-HH-mm.json" -ForegroundColor Gray
    Write-Host "                                     (the yyyy-MM-dd-HH-mm segment is replaced with the run timestamp)" -ForegroundColor Gray
    Write-Host "      -NoBaseline                  skip writing the JSON baselines" -ForegroundColor Gray
    Write-Host
}

function Collect-Executables {
    param(
        [string]$Filter = '*.exe'
    )

    Write-Host "Scanning directories using filter '$Filter':" -ForegroundColor Cyan
    $paths | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    Write-Host

    $files = foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Recurse -Filter $Filter -File -ErrorAction SilentlyContinue
        }
    }

    if (-not $files) {
        Write-Warning "No files matched the specified filter in the target directories."
    }

    return $files
}

function Collect-Signatures {
    param(
        [System.IO.FileInfo[]]$Files,
        [string]$ActivityLabel
    )

    if (-not $Files) {
        return @()
    }

    $results = @()
    $total = $Files.Count
    $index = 0

    foreach ($file in $Files) {
        $index++
        $percent = [int](($index / $total) * 100)

        Write-Progress -Activity $ActivityLabel `
                       -Status   "$percent% - $($file.FullName)" `
                       -PercentComplete $percent

        try {
            $sig = Get-AuthenticodeSignature -FilePath $file.FullName
            $results += [PSCustomObject]@{
                Path           = $file.FullName
                Status         = $sig.Status
                StatusMessage  = $sig.StatusMessage
                RawCertificate = $sig.SignerCertificate
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Path           = $file.FullName
                Status         = 'Error'
                StatusMessage  = $_.Exception.Message
                RawCertificate = $null
            }
        }
    }

    Write-Progress -Activity $ActivityLabel -Completed
    return $results
}

function Pause-ForMenu {
    if (-not $script:ShouldPause) {
        return
    }

    Read-Host "Press Enter to return to the menu" | Out-Null
    Write-Host
}

function Ensure-AllExeResults {
    if (-not $script:AllExeResults) {
        $files = Collect-Executables -Filter '*.exe'
        if (-not $files) { return $false }
        $script:AllExeResults = Collect-Signatures -Files $files -ActivityLabel 'Scanning executables'
    }
    return $true
}

function Ensure-SearchHostResults {
    if (-not $script:SearchHostResults) {
        $files = Collect-Executables -Filter '*SearchHost.exe'
        if (-not $files) { return $false }
        $script:SearchHostResults = Collect-Signatures -Files $files -ActivityLabel 'Scanning SearchHost.exe (Option C)'
    }
    return $true
}

function Save-Baseline {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.IEnumerable]$Items,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$ContextLabel = 'Baseline'
    )

    if ($NoBaseline) {
        Write-Host "Baseline generation skipped (--nobaseline)." -ForegroundColor DarkGray
        return
    }

    $paths = $Items | Select-Object -ExpandProperty Path -Unique
    if (-not $paths) {
        Write-Host "No valid executables to store in baseline." -ForegroundColor Yellow
        return
    }

    $now = Get-Date
    $payload = [ordered]@{
        generatedOn = $now.ToString('o')
        total       = $paths.Count
        paths       = $paths
    }

    $resolvedBaseline = $Path
    if ($resolvedBaseline -match 'yyyy-MM-dd-HH-mm') {
        $resolvedBaseline = $resolvedBaseline -replace 'yyyy-MM-dd-HH-mm', $now.ToString('yyyy-MM-dd-HH-mm')
    }

    $targetPath = [System.IO.Path]::GetFullPath($resolvedBaseline)
    $dir = Split-Path -Path $targetPath -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $payload | ConvertTo-Json -Depth 5 | Out-File -FilePath $targetPath -Encoding UTF8
    Write-Host "$ContextLabel baseline saved to: $targetPath" -ForegroundColor Green
}

function Show-StatusSummary {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.IEnumerable]$Items,
        [string]$Context = 'Current selection'
    )

    if (-not $Items) { return }

    Write-Host "$Context status breakdown:" -ForegroundColor Cyan
    $Items |
        Group-Object Status |
        Sort-Object Count -Descending |
        ForEach-Object {
            Write-Host ("  - {0,-12} : {1,5}" -f $_.Name, $_.Count) -ForegroundColor Gray
        }
    $hasTrustWarning = $Items | Where-Object { $_.StatusMessage -eq $script:TrustProviderWarning }
    if ($hasTrustWarning) {
        Write-Host "    * Trust provider warning detected once: $($script:TrustProviderWarning)" -ForegroundColor DarkGray
    }
    Write-Host "    * 'UnknownError' often indicates unsigned files or restricted WinSxS copies." -ForegroundColor DarkGray
    Write-Host
}

function Show-OptionA {
    if (-not (Ensure-AllExeResults)) { return }

    Write-Host "Option A lists executables whose Authenticode status is anything other than 'Valid'." -ForegroundColor Yellow
    Write-Host "Only the status and path are shown so you can focus on potential issues." -ForegroundColor Yellow
    Write-Host "A JSON baseline of these paths is saved unless -NoBaseline is specified." -ForegroundColor Yellow
    Write-Host

    $nonValid = $script:AllExeResults | Where-Object { $_.Status -ne 'Valid' }

    if (-not $nonValid) {
        Write-Host "All scanned executables are reported as Valid." -ForegroundColor Green
    } else {
        $nonValid |
            Select-Object @{Name='Status'; Expression={$_.Status}},
                          @{Name='Path';   Expression={$_.Path}} |
            Format-Table -AutoSize -Wrap

        Write-Host "\nTotal: $($nonValid.Count) executable(s) need attention." -ForegroundColor Cyan
        Show-StatusSummary -Items $nonValid -Context 'Non-Valid executables'
        Save-Baseline -Items $nonValid -Path $InvalidBaselinePath -ContextLabel 'Invalid executables'
    }

    Pause-ForMenu
}

function Show-OptionB {
    if (-not (Ensure-AllExeResults)) { return }

    Write-Host "Option B lists every executable along with its signer certificate summary, status, and path." -ForegroundColor Yellow
    Write-Host "Use this to review certificate subjects and thumbprints." -ForegroundColor Yellow
    Write-Host

    $script:AllExeResults |
        Select-Object @{Name='SignerCertificate'; Expression={ Format-SignerCertificate $_.RawCertificate }},
                      @{Name='Status';            Expression={$_.Status}},
                      @{Name='Path';              Expression={$_.Path}} |
        Format-Table -AutoSize -Wrap

    Show-StatusSummary -Items $script:AllExeResults -Context 'All executables'

    Pause-ForMenu
}

function Show-OptionC {
    if (-not (Ensure-SearchHostResults)) { return }

    Write-Host "Option C focuses on SearchHost.exe instances within the scanned directories." -ForegroundColor Yellow
    Write-Host "This helps validate that the Windows search component binaries are signed as expected." -ForegroundColor Yellow
    Write-Host

    if (-not $script:SearchHostResults) {
        Write-Host "No SearchHost.exe files were found in the target directories." -ForegroundColor Yellow
    } else {
        $script:SearchHostResults |
            Select-Object @{Name='SignerCertificate'; Expression={ Format-SignerCertificate $_.RawCertificate }},
                          @{Name='Status';            Expression={$_.Status}},
                          @{Name='Path';              Expression={$_.Path}} |
            Format-Table -AutoSize -Wrap
        Show-StatusSummary -Items $script:SearchHostResults -Context 'SearchHost executables'
    }

    Pause-ForMenu
}

function Show-OptionD {
    if (-not (Ensure-AllExeResults)) { return }

    Write-Host "Option D lists only executables with a 'Valid' Authenticode status and can write a reusable baseline JSON." -ForegroundColor Yellow
    Write-Host "Use this when you want a reference of trusted binaries for later comparison." -ForegroundColor Yellow
    Write-Host

    $valid = $script:AllExeResults | Where-Object { $_.Status -eq 'Valid' }

    if (-not $valid) {
        Write-Host "No executables were reported as Valid." -ForegroundColor Yellow
    } else {
        $valid |
            Select-Object @{Name='SignerCertificate'; Expression={ Format-SignerCertificate $_.RawCertificate }},
                          @{Name='Path';              Expression={$_.Path}} |
            Format-Table -AutoSize -Wrap

        Show-StatusSummary -Items $valid -Context 'Valid executables'
        Save-Baseline -Items $valid -Path $BaselinePath -ContextLabel 'Valid executables'
    }

    Pause-ForMenu
}

function Start-AuthenticodeMenu {
    $script:ShouldPause = $true
    Show-AuthenticodeUsage
    do {
        Write-Host "================ Authenticode Signature Menu ================" -ForegroundColor Cyan
        Write-Host "Choose what to scan BEFORE any directories are crawled. Once a scan completes, results are cached for reuse." -ForegroundColor Gray
        Write-Host "A) Show executables with non-Valid signature status (Status, Path)"
        Write-Host "B) Show all executables with signer certificate details (SignerCertificate, Status, Path)"
        Write-Host "C) Show all SearchHost.exe instances with signer certificate details"
        Write-Host "D) Show Valid executables and optionally write a baseline JSON"
        Write-Host "Q) Quit"
        $choice = Read-Host 'Select an option'

        switch ($choice.ToUpperInvariant()) {
            'A' { Show-OptionA }
            'B' { Show-OptionB }
            'C' { Show-OptionC }
            'D' { Show-OptionD }
            'Q' { Write-Host 'Exiting menu.' }
            Default { Write-Warning 'Invalid selection. Please choose A, B, C, or Q.' }
        }
    } while ($choice.ToUpperInvariant() -ne 'Q')
}

switch ($Mode.ToLowerInvariant()) {
    'menu' {
        Start-AuthenticodeMenu
    }
    'show-exec-invalid' {
        $script:ShouldPause = -not $ShowMenuAfterBatch
        Show-OptionA
        if ($ShowMenuAfterBatch) { Start-AuthenticodeMenu }
    }
    'show-exec-details' {
        $script:ShouldPause = -not $ShowMenuAfterBatch
        Show-OptionB
        if ($ShowMenuAfterBatch) { Start-AuthenticodeMenu }
    }
    'show-searchhost' {
        $script:ShouldPause = -not $ShowMenuAfterBatch
        Show-OptionC
        if ($ShowMenuAfterBatch) { Start-AuthenticodeMenu }
    }
    'show-exec-valid' {
        $script:ShouldPause = -not $ShowMenuAfterBatch
        Show-OptionD
        if ($ShowMenuAfterBatch) { Start-AuthenticodeMenu }
    }
    default {
        Write-Warning "Unknown mode '$Mode'. Starting interactive menu."
        Start-AuthenticodeMenu
    }
}
