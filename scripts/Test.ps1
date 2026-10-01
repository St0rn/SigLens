$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Py)) {
    Write-Host "[ERROR] Install first with Install.ps1 -Dev" -ForegroundColor Red
    exit 1
}

$OldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $Root "src")

Push-Location $Root
try {
    & $Py -m pytest -q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
    $env:PYTHONPATH = $OldPythonPath
}
