$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\security\default\0310_Force_Clear_Browsing_Data_MS_Edge.bat"
$id = [guid]::NewGuid().ToString()
$registryKey = "HKCU\Software\Windows10Debloater-Test-$id"
$providerPath = "HKCU:\Software\Windows10Debloater-Test-$id"
$testPath = Join-Path ([IO.Path]::GetTempPath()) ("edge-policy-test-$id.bat")

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

try {
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $target = "HKLM\SOFTWARE\Policies\Microsoft\Edge"
    Assert-Test ($source.Contains($target) -and -not $source.Contains("Microsoft\Windows\System")) "Incorrect production policy path."
    # Run the same batch logic against an isolated current-user key.
    [IO.File]::WriteAllText($testPath, $source.Replace($target, $registryKey), [Text.Encoding]::ASCII)
    foreach ($scenario in @("Missing key", "Repeat run", "Existing zero")) {
        if ($scenario -eq "Existing zero") {
            Set-ItemProperty -LiteralPath $providerPath -Name ClearBrowsingDataOnExit -Value 0 -Type DWord
        }
        $output = & $env:ComSpec /d /c "`"$testPath`"" 2>&1
        Assert-Test ($LASTEXITCODE -eq 0) "${scenario}: batch failed: $output"
        $value = Get-ItemPropertyValue -LiteralPath $providerPath -Name ClearBrowsingDataOnExit
        Assert-Test ($value -eq 1) "${scenario}: incorrect value."
        $key = Get-Item -LiteralPath $providerPath
        try {
            Assert-Test ($key.GetValueKind("ClearBrowsingDataOnExit") -eq [Microsoft.Win32.RegistryValueKind]::DWord) "${scenario}: incorrect registry type."
        }
        finally { $key.Dispose() }
        Assert-Test (($output -join "`n").Contains("[confirmed] ClearBrowsingDataOnExit = 1")) "${scenario}: missing confirmation."
        Write-Host "[PASS] $scenario."
    }
}
finally {
    if (Test-Path -LiteralPath $providerPath) { Remove-Item -LiteralPath $providerPath -Force }
    if (Test-Path -LiteralPath $testPath) { Remove-Item -LiteralPath $testPath -Force }
}
