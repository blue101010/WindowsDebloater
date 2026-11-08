#Set-Location -Path "C:\Windows\System32"

Write-Host "[0080_List_BITS] List BITS (Background Intelligent Transfer Service) "
# List BITS (Background Intelligent Transfer Service) jobs details (ref Windows update for example)
Get-BitsTransfer

# Get-BitsTransfer -AllUsers -Verbose
