[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Clam = Join-Path $Root "tools\clamav"
$Fresh = Join-Path $Clam "freshclam.exe"
$Conf = Join-Path $Clam "freshclam.conf"

if (-not (Test-Path $Fresh)) {
    Write-Host "[ERROR] Portable ClamAV is not installed. Run .\scripts\Install-AVs.ps1" -ForegroundColor Red
    exit 1
}

& $Fresh "--config-file=$Conf"
exit $LASTEXITCODE
