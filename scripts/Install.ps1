[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$AddToUserPath,
    [switch]$SkipAVInstall
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv"

Write-Host "=== SigLens Installer ===" -ForegroundColor Cyan
Write-Host "Root: $Root"

# winget/MSI may have changed the User/Machine PATH after this PowerShell
# process was started. Refresh it before looking for Python.
$MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = (($MachinePath, $UserPath) -join ";").Trim(";")

function Test-PythonExecutable {
    param([Parameter(Mandatory=$true)][string]$Exe)
    try {
        if (-not (Test-Path -LiteralPath $Exe)) { return $null }
        $Json = & $Exe -c "import json,sys; print(json.dumps({'major':sys.version_info.major,'minor':sys.version_info.minor,'micro':sys.version_info.micro,'exe':sys.executable}))" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $Json) { return $null }
        $Info = $Json | ConvertFrom-Json
        if (($Info.major -gt 3) -or (($Info.major -eq 3) -and ($Info.minor -ge 11))) {
            return [PSCustomObject]@{
                Exe = [string]$Info.exe
                Version = [version]("{0}.{1}.{2}" -f $Info.major,$Info.minor,$Info.micro)
            }
        }
    } catch {}
    return $null
}

$PythonCandidates = New-Object System.Collections.Generic.List[string]

# 1) Python Launcher: enumerate every interpreter it knows about.
$PyCmd = Get-Command py.exe -ErrorAction SilentlyContinue
if ($PyCmd) {
    try {
        $PyList = & $PyCmd.Source -0p 2>$null
        foreach ($Line in $PyList) {
            # py -0p lines end with the full python.exe path.
            if ($Line -match '([A-Za-z]:\\.*?python(?:\.exe)?)\s*$') {
                $PythonCandidates.Add($Matches[1])
            }
        }
    } catch {}
}

# 2) Commands visible in PATH.
foreach ($Name in @("python.exe", "python3.exe")) {
    $Cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($Cmd -and $Cmd.Source) { $PythonCandidates.Add($Cmd.Source) }
}

# 3) Standard per-user and machine installation locations.
$Patterns = @(
    (Join-Path $env:LOCALAPPDATA "Programs\\Python\\Python*\\python.exe"),
    (Join-Path $env:ProgramFiles "Python*\\python.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Python*\\python.exe")
)
foreach ($Pattern in $Patterns) {
    if ($Pattern) {
        Get-ChildItem -Path $Pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
            $PythonCandidates.Add($_.FullName)
        }
    }
}

# Deduplicate, validate and select the newest Python >= 3.11.
$Valid = @()
foreach ($Candidate in ($PythonCandidates | Select-Object -Unique)) {
    $Info = Test-PythonExecutable -Exe $Candidate
    if ($Info) { $Valid += $Info }
}

if (-not $Valid -or $Valid.Count -eq 0) {
    Write-Host "[ERROR] Python 3.11+ not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Python may have just been installed by winget. Reopen PowerShell or run:"
    Write-Host '$env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")' -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Useful diagnostics:"
    Write-Host "  py -0p"
    Write-Host "  Get-ChildItem `$env:LOCALAPPDATA\\Programs\\Python\\Python*\\python.exe"
    Write-Host ""
    Write-Host "Recommended install: winget install -e --id Python.Python.3.12"
    exit 1
}

$Selected = $Valid | Sort-Object Version -Descending | Select-Object -First 1
$PythonExe = $Selected.Exe
Write-Host ("[OK] Python {0}: {1}" -f $Selected.Version, $PythonExe) -ForegroundColor Green

if (-not (Test-Path $Venv)) {
    Write-Host "[*] Creating virtual environment..."
    & $PythonExe -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw "Failed to create virtual environment." }
} else {
    Write-Host "[OK] venv already present" -ForegroundColor Green
}

$Py = Join-Path $Venv "Scripts\\python.exe"
$Pip = Join-Path $Venv "Scripts\\pip.exe"
if (-not (Test-Path $Py)) { throw "python.exe missing from venv: $Py" }

Write-Host "[*] Updating pip/setuptools/wheel..."
& $Py -m pip install --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "Failed to update pip/setuptools/wheel." }

if ($Dev) {
    Write-Host "[*] Installing dependencies dev..."
    & $Py -m pip install -r (Join-Path $Root "requirements-dev.txt")
} else {
    Write-Host "[*] Installing dependencies..."
    & $Py -m pip install -r (Join-Path $Root "requirements.txt")
}
if ($LASTEXITCODE -ne 0) { throw "Failed to install dependencies." }



# Create a command shim without installing SigLens as a versioned Python package.
$Shim = Join-Path $Venv "Scripts\siglens.cmd"
$Launcher = Join-Path $Root "siglens_launcher.py"
$ShimContent = "@echo off`r`n`"$Py`" `"$Launcher`" %*`r`n"
Set-Content -LiteralPath $Shim -Value $ShimContent -Encoding ASCII
Write-Host "[OK] CLI shim: $Shim" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path (Join-Path $Root "reports") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root "tools") | Out-Null

if ($AddToUserPath) {
    $Bin = Join-Path $Venv "Scripts"
    $Current = [Environment]::GetEnvironmentVariable("Path", "User")
    $Parts = @($Current -split ";" | Where-Object { $_ })
    if (-not ($Parts -contains $Bin)) {
        $NewPath = (($Parts + $Bin) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        Write-Host "[OK] Added to user PATH: $Bin" -ForegroundColor Green
    }
    if (-not (($env:Path -split ";") -contains $Bin)) {
        $env:Path += ";$Bin"
    }
}

if (-not $SkipAVInstall) {
    Write-Host ""
    Write-Host "[*] Installing/updating local AV engines..."
    & (Join-Path $PSScriptRoot "Install-AVs.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] AV setup returned exit code $LASTEXITCODE" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "[OK] Installation complete." -ForegroundColor Green
Write-Host "Test: .\\scripts\\SigLens.ps1 doctor"
Write-Host "Scan: .\\scripts\\SigLens.ps1 scan .\\sample.exe"
Write-Host "CLI: siglens doctor (after reopening the terminal if PATH was updated)"
