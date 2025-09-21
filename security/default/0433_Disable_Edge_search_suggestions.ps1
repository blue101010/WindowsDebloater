# Privacy - Disable search suggestions in Edge.

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes"
$name = "ShowSearchSuggestionsGlobal"
$value = 0

# Create registry path if it doesn't exist
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Output "Created registry path: $registryPath"
}

# Check current value before changing
$currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue
if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
    # Set the registry value
    Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord
    Write-Output "Disabled Edge search suggestions"
} else {
    Write-Output "Edge search suggestions are already disabled"
}