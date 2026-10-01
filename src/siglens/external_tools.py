from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import sys

from .utils import resolve_tool, run_command


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if exe_dir.name.lower() == "dist":
            return exe_dir.parent
        return exe_dir
    return Path(__file__).resolve().parents[2]


def find_mpcmdrun() -> str | None:
    direct = Path(os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"))
    if direct.exists():
        return str(direct)

    platform = Path(os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Platform"))
    if platform.exists():
        for version_dir in sorted([p for p in platform.iterdir() if p.is_dir()], reverse=True):
            exe = version_dir / "MpCmdRun.exe"
            if exe.exists():
                return str(exe)

    return shutil.which("MpCmdRun.exe")


def _powershell_json(script: str, timeout: int = 45) -> dict:
    result = run_command(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )
    if result.get("stdout"):
        try:
            result["json"] = json.loads(result["stdout"])
        except Exception:
            pass
    return result


def defender_detections_for_path(path: Path) -> dict:
    target = str(path.resolve()).replace("'", "''")
    script = f"""
$Target = '{target}'
$Detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
$ThreatMap = @{{}}
foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) {{
    $ThreatMap[[string]$t.ThreatID] = $t
}}
$Rows = foreach ($d in $Detections) {{
    $Resources = @($d.Resources | ForEach-Object {{ [string]$_ }})
    $Match = $false
    foreach ($r in $Resources) {{
        if ($r -like \"*$Target*\") {{ $Match = $true; break }}
    }}
    if ($Match) {{
        $Threat = $ThreatMap[[string]$d.ThreatID]
        [pscustomobject]@{{
            ThreatID = $d.ThreatID
            ThreatName = if ($Threat) {{ $Threat.ThreatName }} else {{ $null }}
            InitialDetectionTime = $d.InitialDetectionTime
            LastThreatStatusChangeTime = $d.LastThreatStatusChangeTime
            ActionSuccess = $d.ActionSuccess
            Resources = $Resources
        }}
    }}
}}
@($Rows) | ConvertTo-Json -Compress -Depth 6
"""
    return _powershell_json(script)


def defender_scan(path: Path) -> dict:
    exe = find_mpcmdrun()
    if not exe:
        return {"available": False, "error": "MpCmdRun.exe not found"}

    result = run_command([exe, "-Scan", "-ScanType", "3", "-File", str(path)], timeout=300)
    result["available"] = True
    result["engine_path"] = exe
    result["detections"] = defender_detections_for_path(path)
    return result


def defender_status() -> dict:
    script = (
        "Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureVersion,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    )
    result = _powershell_json(script, timeout=30)
    if "json" in result:
        result["status"] = result["json"]
    return result


def find_clamscan() -> str | None:
    root = project_root()
    candidates = [
        root / "tools" / "clamav" / "clamscan.exe",
        root / "tools" / "clamscan.exe",
        Path(r"C:\Program Files\ClamAV\clamscan.exe"),
        Path(r"C:\ClamAV\clamscan.exe"),
    ]

    path_match = shutil.which("clamscan.exe") or shutil.which("clamscan")
    if path_match:
        candidates.insert(0, Path(path_match))

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def clamav_scan(path: Path) -> dict:
    exe = find_clamscan()
    if not exe:
        return {
            "available": False,
            "error": r"clamscan.exe not found. Run scripts\Install-AVs.ps1.",
        }

    install_dir = Path(exe).parent
    database_dir = install_dir / "database"
    args = [exe, "--no-summary"]
    if database_dir.exists():
        args.append(f"--database={database_dir}")
    args.append(str(path))

    result = run_command(args, timeout=300)
    result["available"] = True
    result["engine_path"] = exe
    result["database_path"] = str(database_dir) if database_dir.exists() else None
    return result


def capa_scan(path: Path) -> dict:
    exe = resolve_tool("capa.exe", project_root()) or resolve_tool("capa", project_root())
    if not exe:
        return {"available": False, "error": "capa not found"}

    result = run_command([exe, "-j", str(path)], timeout=300)
    result["available"] = True
    if result.get("stdout"):
        try:
            result["json"] = json.loads(result["stdout"])
        except Exception:
            pass
    return result
