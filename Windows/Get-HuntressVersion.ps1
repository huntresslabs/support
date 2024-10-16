# Simple way to check for Huntress version via PowerShell

if (Test-Path "C:\Program Files\Huntress\HuntressAgent.exe"){
    Write-Host "Huntress version (64bit): "(Get-Item "C:\Program Files\Huntress\HuntressAgent.exe").VersionInfo.FileVersion
    Write-Host "Process Insights Rio EDR version: "(Get-Item "C:\Program Files\Huntress\Rio\Rio.exe").VersionInfo.FileVersion
} elseif (Test-Path "C:\Program Files (x86)\Huntress\HuntressAgent.exe") {
    Write-Host "Huntress version (32bit): "(Get-Item "C:\Program Files (x86)\Huntress\HuntressAgent.exe").VersionInfo.FileVersion
    Write-Host "Process Insights Rio EDR version: "(Get-Item "C:\Program Files (x86)\Huntress\Rio\Rio.exe").VersionInfo.FileVersion
} else {
    Write-Host "Huntress not found!"}
