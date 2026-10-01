$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Write-Host "=== SigLens Doctor ===" -ForegroundColor Cyan

$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (Test-Path $VenvPy) {
    Write-Host "[OK] venv present" -ForegroundColor Green
    & $VenvPy --version
} else {
    Write-Host "[FAIL] venv missing" -ForegroundColor Red
}

$Cli = Join-Path $Root ".venv\Scripts\siglens.exe"
if (Test-Path $Cli) {
    Write-Host "[OK] CLI present" -ForegroundColor Green
    & $Cli doctor
} else {
    Write-Host "[FAIL] CLI missing" -ForegroundColor Red
}

$Mp = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($Mp) {
    Write-Host "[OK] Microsoft Defender CLI: $($Mp.FullName)" -ForegroundColor Green
} elseif (Test-Path "$env:ProgramFiles\Windows Defender\MpCmdRun.exe") {
    Write-Host "[OK] Microsoft Defender CLI" -ForegroundColor Green
} else {
    Write-Host "[WARN] MpCmdRun.exe not found" -ForegroundColor Yellow
}

foreach ($tool in @("capa.exe", "clamscan.exe")) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    $local = Join-Path $Root "tools\$tool"
    if ($cmd) {
        Write-Host "[OK] $tool : $($cmd.Source)" -ForegroundColor Green
    } elseif (Test-Path $local) {
        Write-Host "[OK] $tool : $local" -ForegroundColor Green
    } else {
        Write-Host "[INFO] $tool not installed (optional)" -ForegroundColor DarkGray
    }
}

$Cfg = Join-Path $Root "engines.json"
if (Test-Path $Cfg) {
    Write-Host "[OK] Multi-AV config: $Cfg" -ForegroundColor Green
} else {
    Write-Host "[WARN] engines.json missing; copie engines.example.json" -ForegroundColor Yellow
}

$ClamLocal = Join-Path $Root "tools\clamav\clamscan.exe"
if (Test-Path $ClamLocal) {
    Write-Host "[OK] Portable ClamAV: $ClamLocal" -ForegroundColor Green
    $Db = Join-Path $Root "tools\clamav\database"
    $Count = @(Get-ChildItem $Db -File -ErrorAction SilentlyContinue).Count
    Write-Host "[INFO] ClamAV database files: $Count" -ForegroundColor DarkGray
} else {
    Write-Host "[WARN] Portable ClamAV not installed. Run scripts\Install-AVs.ps1" -ForegroundColor Yellow
}
