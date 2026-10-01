[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root "tools"
$Clam = Join-Path $Tools "clamav"
$Version = "1.5.4"
$Url = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$Version/clamav-$Version.win.x64.zip"
$ExpectedSha256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395"
$Zip = Join-Path $env:TEMP "siglens-clamav-$Version.zip"
$Extract = Join-Path $env:TEMP "siglens-clamav-$Version"

New-Item -ItemType Directory -Force -Path $Tools | Out-Null
Write-Host "=== SigLens AV Setup ===" -ForegroundColor Cyan

try {
    $D = Get-MpComputerStatus -ErrorAction Stop
    Write-Host ("[OK] Microsoft Defender: AntivirusEnabled={0}, signatures={1}" -f $D.AntivirusEnabled,$D.AntivirusSignatureVersion) -ForegroundColor Green
} catch {
    Write-Host "[WARN] Microsoft Defender status could not be read." -ForegroundColor Yellow
}

if ((Test-Path (Join-Path $Clam "clamscan.exe")) -and -not $Force) {
    Write-Host "[OK] Portable ClamAV already installed: $Clam" -ForegroundColor Green
} else {
    if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
    if (Test-Path $Clam) { Remove-Item -Recurse -Force $Clam }

    Write-Host "[*] Downloading official ClamAV $Version portable x64 package..."
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Zip

    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Zip).Hash.ToLowerInvariant()
    if ($Actual -ne $ExpectedSha256) {
        Remove-Item -Force $Zip -ErrorAction SilentlyContinue
        throw "ClamAV package SHA256 mismatch. Expected $ExpectedSha256, got $Actual"
    }
    Write-Host "[OK] ClamAV package hash verified." -ForegroundColor Green

    Expand-Archive -LiteralPath $Zip -DestinationPath $Extract -Force
    $Inner = Get-ChildItem -Path $Extract -Directory | Select-Object -First 1
    if (-not $Inner) { throw "ClamAV archive layout not recognized." }
    Move-Item -LiteralPath $Inner.FullName -Destination $Clam
    Remove-Item -Recurse -Force $Extract -ErrorAction SilentlyContinue
    Remove-Item -Force $Zip -ErrorAction SilentlyContinue
    Write-Host "[OK] ClamAV installed to $Clam" -ForegroundColor Green
}

$FreshSample = Join-Path $Clam "conf_examples\freshclam.conf.sample"
$FreshConf = Join-Path $Clam "freshclam.conf"
$Database = Join-Path $Clam "database"
New-Item -ItemType Directory -Force -Path $Database | Out-Null

if ((Test-Path $FreshSample) -and (-not (Test-Path $FreshConf) -or $Force)) {
    $Content = Get-Content -LiteralPath $FreshSample
    $Content = $Content | Where-Object { $_.Trim() -ne "Example" }
    $Content += "DatabaseDirectory `"$Database`""
    Set-Content -LiteralPath $FreshConf -Value $Content -Encoding ASCII
}

$Fresh = Join-Path $Clam "freshclam.exe"
if (Test-Path $Fresh) {
    Write-Host "[*] Updating ClamAV signature databases..."
    & $Fresh "--config-file=$FreshConf"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] freshclam returned exit code $LASTEXITCODE. ClamAV is installed, but signatures may need a manual update." -ForegroundColor Yellow
    } else {
        Write-Host "[OK] ClamAV signatures updated." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Commercial engines (ESET, Sophos, Avast, Malwarebytes) are not installed automatically." -ForegroundColor DarkGray
Write-Host "SigLens uses them when their licensed CLI scanner is already installed and enabled in engines.json." -ForegroundColor DarkGray
