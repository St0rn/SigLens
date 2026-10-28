from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event
from time import perf_counter
from typing import Callable

from . import __author__, __version__
from .amsi_scan import scan_file as amsi_scan_file
from .dissection import dissect_pe
from .fileio import normalize_path, read_file_bytes
from .iocs import extract_iocs
from .multiav import scan_engines
from .pe_analyzer import analyze_pe
from .refactor import build_refactor_hints
from .report import report_metadata
from .strings import extract_strings
from .utils import entropy, hashes
from .yara_scan import scan as yara_scan
from .ghidra import build_ghidra_locations


class AnalysisCancelled(RuntimeError):
    pass


ProgressCallback = Callable[[str, int], None]


@dataclass(frozen=True)
class AnalysisOptions:
    yara_path: Path | None = None
    engines_path: Path | None = None
    run_amsi: bool = False
    extract_iocs: bool = True
    dissect_pe: bool = True
    strings_limit: int = 300


@dataclass
class AnalysisResult:
    path: Path
    data: bytes
    report: dict


def _notify(callback: ProgressCallback | None, message: str, percent: int) -> None:
    if callback:
        callback(message, percent)


def _check_cancel(cancel_event: Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelled("Analysis cancelled")


def analyze_artifact(
    path: Path,
    options: AnalysisOptions | None = None,
    *,
    cancel_event: Event | None = None,
    progress: ProgressCallback | None = None,
) -> AnalysisResult:
    """Run reusable analysis for the GUI or another non-CLI caller.

    Cancellation is cooperative between stages. An external AV process already
    running is allowed to finish so its own cleanup and timeout handling remain
    authoritative.
    """
    options = options or AnalysisOptions()
    started = perf_counter()
    _check_cancel(cancel_event)
    _notify(progress, "Reading artifact", 5)
    path, data, io_meta = read_file_bytes(path)

    _check_cancel(cancel_event)
    _notify(progress, "Static analysis", 20)
    strings = extract_strings(data, max(1, options.strings_limit))
    report = {
        **report_metadata("artifact_analysis"),
        "tool": {"name": "SigLens", "version": __version__, "author": __author__},
        "file": {
            "path": str(path),
            "hashes": hashes(path, data),
            "entropy": round(entropy(data), 3),
            "io": io_meta,
        },
        "pe": analyze_pe(path, data),
        "yara": {"requested": bool(options.yara_path), "available": False, "matches": []},
        "multiav": {"requested": bool(options.engines_path), "results": [], "summary": {}},
        "amsi": {"requested": options.run_amsi},
        "iocs": {},
        "dissection": {},
        "correlations": [],
        "component_scan": {},
        "window_scan": {},
        "ghidra_locations": [],
        "script_analysis": {},
        "strings_summary": {
            "ascii_count_shown": len(strings["ascii"]),
            "utf16_count_shown": len(strings["utf16le"]),
            "ascii": strings["ascii"],
            "utf16le": strings["utf16le"],
            "truncated": strings["truncated"],
        },
        "limitations": [],
    }

    _check_cancel(cancel_event)
    if options.dissect_pe:
        _notify(progress, "PE dissection", 35)
        report["dissection"] = dissect_pe(path, data)

    _check_cancel(cancel_event)
    if options.yara_path:
        _notify(progress, "YARA rules", 50)
        report["yara"] = yara_scan(path, normalize_path(options.yara_path), data=data)

    _check_cancel(cancel_event)
    if options.extract_iocs:
        _notify(progress, "IOC extraction", 60)
        report["iocs"] = extract_iocs(strings["ascii"] + strings["utf16le"])

    _check_cancel(cancel_event)
    if options.engines_path:
        _notify(progress, "AV engines", 72)
        try:
            report["multiav"] = scan_engines(path, normalize_path(options.engines_path))
            report["multiav"]["requested"] = True
        except Exception as exc:
            report["multiav"] = {
                "requested": True,
                "results": [],
                "summary": {},
                "error": f"{type(exc).__name__}: {exc}",
            }

    _check_cancel(cancel_event)
    if options.run_amsi:
        _notify(progress, "AMSI full-buffer scan", 85)
        report["amsi"] = amsi_scan_file(path)
        if not report["amsi"].get("available"):
            report["limitations"].append("Native AMSI was unavailable on this host.")

    _check_cancel(cancel_event)
    _notify(progress, "Finalizing report", 95)
    report["refactor_hints"] = build_refactor_hints(report)
    report["ghidra_locations"] = build_ghidra_locations(path, data, report)
    report["timings"] = {
        "total_ms": round((perf_counter() - started) * 1000, 3),
    }
    _notify(progress, "Complete", 100)
    return AnalysisResult(path=path, data=data, report=report)
