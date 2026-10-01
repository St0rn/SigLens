[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$ArgsRemaining
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"
$Launcher = Join-Path $Root "siglens_launcher.py"

if (-not (Test-Path $Py)) {
    Write-Host "[ERROR] SigLens environment is not installed." -ForegroundColor Red
    Write-Host "Run: .\scripts\Install.ps1"
    exit 1
}

& $Py $Launcher @ArgsRemaining
exit $LASTEXITCODE
