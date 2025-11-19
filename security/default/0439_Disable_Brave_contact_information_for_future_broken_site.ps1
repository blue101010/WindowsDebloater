# Disable Store contact information for future broken site reports in Brave browser
# ref Brave 1.84.139 "Shields menu"
#webcompat": {
#      "report": { "contact_info": "", "enable_save_contact_info": false }
#    },  
# What Contact Information Does This Store?
#This is your personal contact information (typically your email address and optionally your name) 
#that you provide when reporting broken websites to Brave
# Remember a user's contact information that they provide in a webcompat report and auto-fill it #40021
# https://github.com/brave/brave-browser/issues/40021


# Close Brave browser before running this script
Write-Host "Closing Brave browser..." -ForegroundColor Yellow
Get-Process -Name "brave" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$PrefsPath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Preferences"

# Verify Preferences file exists
if (-not (Test-Path $PrefsPath)) {
    Write-Host "Error: Preferences file not found at: $PrefsPath" -ForegroundColor Red
    Write-Host "Make sure Brave has been run at least once." -ForegroundColor Yellow
    exit
}

# Create backup
$BackupPath = "$PrefsPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item $PrefsPath $BackupPath
Write-Host "Backup created: $BackupPath" -ForegroundColor Green

# Read the JSON preferences
$prefs = Get-Content $PrefsPath -Raw | ConvertFrom-Json

# Modify the webcompat settings
if (-not $prefs.webcompat) {
    $prefs | Add-Member -MemberType NoteProperty -Name "webcompat" -Value ([PSCustomObject]@{
        report = [PSCustomObject]@{
            contact_info = ""
            enable_save_contact_info = $false
        }
    })
} else {
    if (-not $prefs.webcompat.report) {
        $prefs.webcompat | Add-Member -MemberType NoteProperty -Name "report" -Value ([PSCustomObject]@{
            contact_info = ""
            enable_save_contact_info = $false
        })
    } else {
        $prefs.webcompat.report.enable_save_contact_info = $false
        $prefs.webcompat.report.contact_info = ""
    }
}

# Save the modified preferences (use depth 100 to preserve entire JSON structure)
$prefs | ConvertTo-Json -Depth 100 -Compress:$false | Set-Content $PrefsPath -Encoding UTF8

Write-Host "`nSuccess! Contact information storage has been disabled." -ForegroundColor Green
Write-Host "Setting: webcompat.report.enable_save_contact_info = false" -ForegroundColor Cyan
Write-Host "`nYou can now restart Brave browser." -ForegroundColor Yellow