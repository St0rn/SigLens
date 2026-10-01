[CmdletBinding()]
param([switch]$Dev)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Py)) {
    Write-Host "[ERROR] Installation missing. Run Install.ps1." -ForegroundColor Red
    exit 1
}

& $Py -m pip install --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "Failed to update pip/setuptools/wheel." }

if ($Dev) {
    & $Py -m pip install --upgrade -r (Join-Path $Root "requirements-dev.txt")
} else {
    & $Py -m pip install --upgrade -r (Join-Path $Root "requirements.txt")
}
if ($LASTEXITCODE -ne 0) { throw "Failed to update dependencies." }

Write-Host "[OK] SigLens dependencies updated." -ForegroundColor Green
Write-Host "[INFO] Source files are used directly; there is no versioned local Python package to update." -ForegroundColor DarkGray
