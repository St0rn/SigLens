[CmdletBinding()]
param(
    [switch]$RemoveReports
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv"

if (Test-Path $Venv) {
    Remove-Item -Recurse -Force $Venv
    Write-Host "[OK] venv removed." -ForegroundColor Green
}

$Bin = Join-Path $Venv "Scripts"
$Current = [Environment]::GetEnvironmentVariable("Path", "User")
if ($Current) {
    $Parts = $Current -split ";" | Where-Object { $_ -and $_ -ne $Bin }
    [Environment]::SetEnvironmentVariable("Path", ($Parts -join ";"), "User")
}

if ($RemoveReports) {
    $Reports = Join-Path $Root "reports"
    if (Test-Path $Reports) {
        Remove-Item -Recurse -Force $Reports
        Write-Host "[OK] reports removeds." -ForegroundColor Green
    }
}

Write-Host "[OK] Local uninstall complete." -ForegroundColor Green
