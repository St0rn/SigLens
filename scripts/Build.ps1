[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Py)) {
    Write-Host "[ERROR] Installation missing. Run Install.ps1 -Dev." -ForegroundColor Red
    exit 1
}

& $Py -m pip install --upgrade pyinstaller
if ($LASTEXITCODE -ne 0) { throw "Failed to install/update PyInstaller." }

Push-Location $Root
try {
    & $Py -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --name "SigLens" `
        --paths "src" `
        --collect-all yara `
        --add-data "src\siglens\templates;siglens\templates" `
        "siglens_launcher.py"
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
} finally {
    Pop-Location
}

$Dist = Join-Path $Root "dist"
Copy-Item (Join-Path $Root "engines.example.json") (Join-Path $Dist "engines.example.json") -Force
Copy-Item (Join-Path $Root "engines.json") (Join-Path $Dist "engines.json") -Force

Write-Host "[OK] Build: $Dist\SigLens.exe" -ForegroundColor Green
Write-Host "[OK] Multi-AV config: $Dist\engines.json" -ForegroundColor Green
