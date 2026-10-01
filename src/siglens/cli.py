from __future__ import annotations
from pathlib import Path
from datetime import datetime
import platform
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import __author__, __product__
from .utils import hashes, entropy
from .fileio import read_file_bytes, normalize_path, path_diagnostics
from .strings import extract_strings
from .pe_analyzer import analyze_pe
from .yara_scan import scan as yara_scan
from .external_tools import defender_scan, defender_status, clamav_scan, capa_scan
from .report import save_json, save_html
from .compare import compare_files
from .refactor import build_refactor_hints
from .amsi_scan import scan_file as amsi_scan_file
from .iocs import extract_iocs
from .dissection import dissect_pe
from .correlation import correlate_offset
from .multiav import scan_engines
from .component_scan import component_scan
from .window_scan import window_scan, MIN_WINDOW_KIB, DEFAULT_WINDOW_KIB
from .region_context import inspect_offset, DEFAULT_PREVIEW_BYTES
from .script_analysis import analyze_script, is_script_path

app = typer.Typer(add_completion=False, help="SigLens - Windows Artifact Analysis and Multi-Engine Scanner")
console = Console()


def _report_paths(path: Path) -> tuple[Path, Path]:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = path.name.replace(" ", "_")
    base = Path.cwd() / "reports" / f"{safe}-{stamp}"
    return base.with_suffix(".json"), base.with_suffix(".html")


def _open_input_or_exit(file: Path) -> tuple[Path, bytes, dict]:
    try:
        return read_file_bytes(file)
    except Exception as exc:
        diag = path_diagnostics(file)
        io_meta = getattr(exc, "siglens_io", None)
        lines = [
            f"Requested file : {file}",
            f"Normalized path : {diag.get('normalized', '<unknown>')}",
            f"Exists : {diag.get('exists')}",
            f"Regular file : {diag.get('is_file')}",
        ]
        if diag.get("size") is not None:
            lines.append(f"Size : {diag['size']} bytes")
        lines.append(f"Final error : {type(exc).__name__}: {exc}")
        if io_meta:
            if io_meta.get("python_error"):
                lines.append(f"Python open() : {io_meta['python_error']}")
            if io_meta.get("win32_error"):
                lines.append(f"CreateFileW : {io_meta['win32_error']}")
        console.print(Panel("\n".join(lines), title="[red]Unable to open file[/red]", border_style="red"))
        console.print("[yellow]Suggested Windows test :[/yellow]")
        console.print(f"  Get-Item -LiteralPath '{diag.get('normalized', str(file))}' | Format-List FullName,Length,Attributes,LinkType,Target")
        console.print("If the file disappears or becomes inaccessible during the test, review Defender/EDR protection history.")
        raise typer.Exit(code=2)


@app.command()
def scan(
    file: Path = typer.Argument(..., dir_okay=False),
    yara: Path | None = typer.Option(None, "--yara", help="YARA rule file or directory"),
    defender: bool = typer.Option(False, "--defender", help="Run Microsoft Defender on the full file"),
    clamav: bool = typer.Option(False, "--clamav", help="Run ClamAV on the full file if available"),
    capa: bool = typer.Option(False, "--capa", help="Run capa if available"),
    symbol_path: Path | None = typer.Option(None, "--symbol-path", help="Local directory containing PDB/symbol files"),
    correlate_yara: bool = typer.Option(True, "--correlate-yara/--no-correlate-yara", help="Correlate YARA offsets to PE/functions/symbols"),
    strings_limit: int = typer.Option(300, "--strings-limit", min=0, max=10000),
    engines: Path | None = typer.Option(None, "--engines", help="Multi-engine AV configuration JSON"),
    amsi: bool = typer.Option(False, "--amsi", help="Scan the complete file buffer through Windows AMSI"),
    iocs: bool = typer.Option(False, "--iocs", help="Extract common IOCs from printable strings"),
    dissect: bool = typer.Option(False, "--dissect", help="Include PE section/resource/overlay dissection"),
    component_scan_enabled: bool = typer.Option(False, "--component-scan", help="Scan fixed PE regions with enabled AV engines"),
    window_scan_enabled: bool = typer.Option(False, "--window-scan", help="Scan fixed non-overlapping windows with enabled AV engines"),
    window_size_kib: int = typer.Option(DEFAULT_WINDOW_KIB, "--window-size", help=f"Fixed window size in KiB (minimum: {MIN_WINDOW_KIB})"),
):
    file, data, io_meta = _open_input_or_exit(file)
    pe = analyze_pe(file, data)
    strings = extract_strings(data, max(strings_limit, 1))
    report = {
        "tool": {"name": "SigLens", "author": __author__},
        "file": {
            "path": str(file),
            "hashes": hashes(file, data),
            "entropy": round(entropy(data), 3),
            "io": io_meta,
        },
        "pe": pe,
        "yara": {"available": False, "matches": []},
        "defender": {"requested": defender},
        "clamav": {"requested": clamav},
        "capa": {"requested": capa},
        "correlations": [],
        "multiav": {"requested": bool(engines), "results": [], "summary": {}},
        "amsi": {"requested": amsi},
        "iocs": {},
        "dissection": {},
        "component_scan": {},
        "window_scan": {},
        "script_analysis": {},
        "strings_summary": {
            "ascii_count_shown": len(strings["ascii"]),
            "utf16_count_shown": len(strings["utf16le"]),
            "ascii": strings["ascii"],
            "utf16le": strings["utf16le"],
            "truncated": strings["truncated"],
        },
    }

    if yara:
        yara = normalize_path(yara)
        y = yara_scan(file, yara, data=data)
        report["yara"] = y
        if correlate_yara:
            seen = set()
            for m in y.get("matches", []):
                for s in m.get("strings", []):
                    off = int(s["offset"])
                    if off not in seen:
                        corr = correlate_offset(file, off, symbol_path=symbol_path, data=data)
                        corr["source"] = {"type": "yara", "rule": m.get("rule"), "identifier": s.get("identifier")}
                        report["correlations"].append(corr)
                        seen.add(off)
                    s["correlation_index"] = next((i for i, c in enumerate(report["correlations"]) if c["offset"] == off), None)

    if defender:
        console.print("[yellow]Warning: Defender may apply its configured remediation or quarantine policy.[/yellow]")
        report["defender"] = defender_scan(file)
        report["defender"]["offset_note"] = "Microsoft Defender CLI does not expose a detection byte offset here."

    if clamav:
        report["clamav"] = clamav_scan(file)

    if capa:
        report["capa"] = capa_scan(file)

    if engines:
        try:
            engines_path = normalize_path(engines)
            report["multiav"] = scan_engines(file, engines_path)
        except Exception as exc:
            report["multiav"] = {
                "requested": True,
                "results": [],
                "summary": {},
                "error": f"{type(exc).__name__}: {exc}",
            }

    if amsi:
        report["amsi"] = amsi_scan_file(file)

    if iocs:
        report["iocs"] = extract_iocs(strings.get("ascii", []) + strings.get("utf16le", []))

    if dissect:
        report["dissection"] = dissect_pe(file, data)

    if component_scan_enabled:
        cfg = normalize_path(engines) if engines else normalize_path(Path("engines.json"))
        report["component_scan"] = component_scan(file, cfg, data)

    if window_scan_enabled:
        if window_size_kib < MIN_WINDOW_KIB:
            raise typer.BadParameter(
                f"--window-size must be at least {MIN_WINDOW_KIB} KiB"
            )
        cfg = normalize_path(engines) if engines else normalize_path(Path("engines.json"))
        report["window_scan"] = window_scan(
            file,
            cfg,
            data,
            window_kib=window_size_kib,
        )

    if is_script_path(file):
        report["script_analysis"] = analyze_script(
            file, data, amsi_result=report.get("amsi") if amsi else None, context_lines=3
        )

    report["refactor_hints"] = build_refactor_hints(report)

    j, h = _report_paths(file)
    save_json(report, j)
    save_html(report, h)

    table = Table(title=f"SigLens")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("File", str(file))
    table.add_row("I/O", io_meta.get("method") or "unknown")
    table.add_row("SHA256", report["file"]["hashes"]["sha256"])
    table.add_row("Size", str(report["file"]["hashes"]["size"]))
    table.add_row("Entropy", str(report["file"]["entropy"]))
    table.add_row("PE", str(pe.get("is_pe", False)))
    table.add_row("YARA matches", str(len(report["yara"].get("matches", []))))
    table.add_row("Correlated offsets", str(len(report["correlations"])))
    if amsi:
        table.add_row("AMSI", str(report.get("amsi", {}).get("status", "unknown")).upper())
    if dissect:
        table.add_row("PE sections", str(len(report.get("dissection", {}).get("sections", []))))
    if window_scan_enabled:
        ws = report.get("window_scan", {})
        table.add_row(
            "Fixed windows",
            f"{ws.get('window_count', 0)} x {ws.get('window_kib', window_size_kib)} KiB / "
            f"{ws.get('detected_window_count', 0)} detected"
        )
    if engines:
        s = report.get("multiav", {}).get("summary", {})
        table.add_row(
            "Multi-AV",
            f"{s.get('detected', 0)} detected / {s.get('clean', 0)} clean / "
            f"{s.get('unknown', 0)} unknown / {s.get('unavailable', 0)} unavailable / {s.get('error', 0)} error"
        )
    table.add_row("JSON", str(j))
    table.add_row("HTML", str(h))
    console.print(table)


@app.command("multi-scan")
def multi_scan(
    file: Path = typer.Argument(..., dir_okay=False),
    engines: Path = typer.Option(Path("engines.json"), "--engines", help="AV engine configuration JSON"),
):
    """Run full-file scans through multiple local AV engines."""
    file, _, _ = _open_input_or_exit(file)
    engines = normalize_path(engines)
    try:
        result = scan_engines(file, engines)
    except Exception as exc:
        console.print(f"[red]Multi-AV error:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(code=2)

    table = Table(title=f"SigLens - Multi-AV")
    table.add_column("Engine")
    table.add_column("Status")
    table.add_column("Signature")
    table.add_column("Offset")
    for r in result.get("results", []):
        status = str(r.get("status", "unknown")).upper()
        signature = str(r.get("signature") or (r.get("error") if r.get("status") == "unavailable" else "-") or "-")
        table.add_row(
            str(r.get("name", "")),
            status,
            signature,
            hex(r["offset"]) if isinstance(r.get("offset"), int) else "not exposed",
        )
    console.print(table)
    console.print("[dim]Mode: full-file scans only; no automatic AV byte-bisection.[/dim]")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path.cwd() / "reports" / f"multiav-{file.stem}-{stamp}.json"
    save_json(result, out)
    console.print(f"[green]JSON:[/green] {out}")


@app.command("component-scan")
def component_scan_command(
    file: Path = typer.Argument(..., dir_okay=False),
    engines: Path = typer.Option(Path("engines.json"), "--engines", help="AV engine configuration JSON"),
):
    """Scan fixed PE sections and overlay with enabled AV engines."""
    file, data, _ = _open_input_or_exit(file)
    engines = normalize_path(engines)
    result = component_scan(file, engines, data)
    if not result.get("is_pe"):
        console.print("[yellow]Input is not a PE file.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"SigLens - PE Region Scan")
    table.add_column("Region")
    table.add_column("Offset")
    table.add_column("RVA")
    table.add_column("Size")
    table.add_column("Detected by")
    for region in result.get("regions", []):
        detected = [
            engine.get("name")
            for engine in region.get("engines", [])
            if engine.get("status") == "detected"
        ]
        table.add_row(
            region.get("name", ""),
            hex(region.get("offset", 0)),
            hex(region["rva"]) if region.get("rva") is not None else "-",
            str(region.get("size", 0)),
            ", ".join(detected) if detected else "-",
        )
    console.print(table)
    console.print("[dim]Fixed PE regions only; no recursive byte bisection.[/dim]")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path.cwd() / "reports" / f"components-{file.stem}-{stamp}.json"
    save_json(result, out)
    console.print(f"[green]JSON:[/green] {out}")


@app.command("narrow")
def window_scan_command(
    file: Path = typer.Argument(
        ...,
        dir_okay=False,
    ),
    engines: Path = typer.Option(
        Path("engines.json"),
        "--engines",
        help="AV engine configuration JSON",
    ),
    max_windows: int = typer.Option(
        2048,
        "--max-windows",
        min=1,
        max=10000,
        help="Maximum number of AV scans performed during narrowing",
    ),
):
    """
    Locate a reproducible AV detection boundary using prefix narrowing.

    The complete file is scanned first. Prefixes of varying lengths are then
    scanned to identify a bounded CLEAN -> DETECTED transition.

    The resulting boundary is inferred from repeated scans. It is not a native
    byte offset supplied by the AV engine.
    """

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def fmt_hex(value, width: int = 8) -> str:
        if value is None:
            return "-"

        try:
            return f"0x{int(value):0{width}X}"
        except Exception:
            return str(value)

    def extract_ascii_strings(
        blob: bytes,
        min_length: int = 4,
    ) -> list[str]:

        result = []
        current = bytearray()

        for byte in blob:
            if 32 <= byte <= 126:
                current.append(byte)

            else:
                if len(current) >= min_length:
                    result.append(
                        current.decode(
                            "ascii",
                            errors="ignore",
                        )
                    )

                current = bytearray()

        if len(current) >= min_length:
            result.append(
                current.decode(
                    "ascii",
                    errors="ignore",
                )
            )

        return result

    def extract_utf16le_strings(
        blob: bytes,
        min_length: int = 4,
    ) -> list[str]:

        result = []
        current = bytearray()
        index = 0

        while index + 1 < len(blob):

            first = blob[index]
            second = blob[index + 1]

            if 32 <= first <= 126 and second == 0:
                current.extend(
                    (
                        first,
                        second,
                    )
                )

            else:
                if len(current) >= min_length * 2:
                    result.append(
                        current.decode(
                            "utf-16le",
                            errors="ignore",
                        )
                    )

                current = bytearray()

            index += 2

        if len(current) >= min_length * 2:
            result.append(
                current.decode(
                    "utf-16le",
                    errors="ignore",
                )
            )

        return result

    def print_hexdump(
        blob: bytes,
        base_offset: int,
    ) -> None:

        for relative in range(
            0,
            len(blob),
            16,
        ):

            chunk = blob[
                relative:relative + 16
            ]

            hex_part = " ".join(
                f"{byte:02x}"
                for byte in chunk
            )

            ascii_part = "".join(
                chr(byte)
                if 32 <= byte <= 126
                else "."
                for byte in chunk
            )

            console.print(
                f"{base_offset + relative:08x}  "
                f"{hex_part:<47}  "
                f"|{ascii_part}|"
            )

    def detected_by_text(row: dict) -> str:

        detected_by = row.get(
            "detected_by",
            [],
        )

        if isinstance(
            detected_by,
            (list, tuple),
        ):
            return (
                ", ".join(
                    str(item)
                    for item in detected_by
                )
                if detected_by
                else "-"
            )

        return (
            str(detected_by)
            if detected_by
            else "-"
        )

    # ------------------------------------------------------------------
    # Input
    # ------------------------------------------------------------------

    file, data, _ = _open_input_or_exit(
        file
    )

    engines = normalize_path(
        engines
    )

    # ------------------------------------------------------------------
    # Run scanner
    # ------------------------------------------------------------------

    try:

        result = window_scan(
            file,
            engines,
            data,
            max_windows=max_windows,
        )

    except Exception as exc:

        console.print(
            "[red]Window scan error:[/red] "
            f"{type(exc).__name__}: {exc}"
        )

        raise typer.Exit(
            code=2
        )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    classification = result.get(
        "classification",
        "UNKNOWN",
    )

    rows = result.get(
        "windows",
        [],
    )

    candidates = result.get(
        "candidates",
        [],
    )

    scan_count = result.get(
        "scan_count",
        len(rows),
    )

    preview_bytes = result.get(
        "context_preview_bytes",
        256,
    )

    try:
        preview_bytes = max(
            16,
            int(preview_bytes),
        )
    except Exception:
        preview_bytes = 256

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    console.print()

    console.print(
        "[bold cyan]"
        "SigLens - Detection Boundary Narrowing"
        "[/bold cyan]"
    )

    console.print(
        f"File           : {file}"
    )

    console.print(
        f"File size      : {len(data)} bytes"
    )

    console.print(
        f"Classification : {classification}"
    )

    console.print(
        f"Scans          : {scan_count}"
    )

    console.print(
        f"Context preview: {preview_bytes} bytes"
    )

    console.print()

    # ------------------------------------------------------------------
    # Prefix scan trace
    # ------------------------------------------------------------------

    trace_table = Table(
        title="Prefix narrowing trace",
    )

    trace_table.add_column(
        "#",
        justify="right",
    )

    trace_table.add_column(
        "Depth",
        justify="right",
    )

    trace_table.add_column(
        "Type",
    )

    trace_table.add_column(
        "Prefix start",
    )

    trace_table.add_column(
        "Prefix end",
    )

    trace_table.add_column(
        "Size",
        justify="right",
    )

    trace_table.add_column(
        "Boundary section",
    )

    trace_table.add_column(
        "Entropy",
    )

    trace_table.add_column(
        "Status",
    )

    trace_table.add_column(
        "Detected by",
    )

    for row in rows:

        index = int(
            row.get(
                "index",
                0,
            )
        )

        depth = int(
            row.get(
                "depth",
                0,
            )
        )

        branch = str(
            row.get(
                "branch",
                "-",
            )
        )

        start = int(
            row.get(
                "start",
                row.get(
                    "offset",
                    0,
                ),
            )
        )

        end = int(
            row.get(
                "end",
                row.get(
                    "end_offset",
                    start,
                ),
            )
        )

        size = int(
            row.get(
                "size",
                max(
                    0,
                    end - start,
                ),
            )
        )

        detected = bool(
            row.get(
                "detected",
                False,
            )
        )

        section = (
            row.get(
                "section"
            )
            or "-"
        )

        entropy_value = row.get(
            "entropy"
        )

        if isinstance(
            entropy_value,
            (int, float),
        ):
            entropy_text = (
                f"{entropy_value:.4f}"
            )
        else:
            entropy_text = "-"

        if detected:
            status = (
                "[red]DETECTED[/red]"
            )
        else:
            status = (
                "[green]CLEAN[/green]"
            )

        trace_table.add_row(
            str(index),
            str(depth),
            branch,
            f"0x{start:08X}",
            f"0x{end:08X}",
            str(size),
            section,
            entropy_text,
            status,
            detected_by_text(row),
        )

    console.print(
        trace_table
    )

    # ------------------------------------------------------------------
    # Candidate boundaries
    # ------------------------------------------------------------------

    for candidate_index, candidate in enumerate(
        candidates
    ):

        console.print()

        boundary_low = candidate.get(
            "boundary_low"
        )

        boundary_high = candidate.get(
            "boundary_high"
        )

        boundary_size = candidate.get(
            "boundary_size"
        )

        # Fallback for older result format.
        if boundary_low is None:
            boundary_low = candidate.get(
                "start",
                candidate.get(
                    "offset",
                    0,
                ),
            )

        if boundary_high is None:
            boundary_high = candidate.get(
                "end",
                candidate.get(
                    "end_offset",
                    boundary_low,
                ),
            )

        boundary_low = int(
            boundary_low
        )

        boundary_high = int(
            boundary_high
        )

        if boundary_size is None:
            boundary_size = max(
                0,
                boundary_high - boundary_low,
            )

        boundary_size = int(
            boundary_size
        )

        candidate_classification = str(
            candidate.get(
                "classification",
                "CANDIDATE_REGION",
            )
        )

        console.print(
            f"[bold cyan]"
            f"Detection boundary #{candidate_index}"
            f"[/bold cyan]"
        )

        console.print(
            f"Classification : {candidate_classification}"
        )

        console.print(
            f"Last CLEAN      : 0x{boundary_low:08X}"
        )

        console.print(
            f"First DETECTED  : 0x{boundary_high:08X}"
        )

        console.print(
            f"Interval        : {boundary_size} bytes"
        )

        console.print(
            f"Detected by     : {detected_by_text(candidate)}"
        )

        reason = candidate.get(
            "reason"
        )

        if reason:
            console.print(
                f"Reason          : {reason}"
            )

        console.print()

        console.print(
            "[yellow]"
            "The CLEAN -> DETECTED boundary is inferred from prefix scans. "
            "It is not an offset supplied directly by the AV engine."
            "[/yellow]"
        )

        # --------------------------------------------------------------
        # PE mapping
        # --------------------------------------------------------------

        section = candidate.get(
            "section"
        )

        rva = candidate.get(
            "rva"
        )

        va = candidate.get(
            "va"
        )

        image_base = candidate.get(
            "image_base"
        )

        console.print()

        console.print(
            "[bold]Boundary mapping[/bold]"
        )

        console.print(
            f"Boundary       : 0x{boundary_high:08X}"
        )

        console.print(
            f"Section        : {section or '-'}"
        )

        console.print(
            f"RVA            : {fmt_hex(rva)}"
        )

        console.print(
            f"VA             : {fmt_hex(va)}"
        )

        console.print(
            f"Image base     : {fmt_hex(image_base)}"
        )

        # --------------------------------------------------------------
        # Hexdump around inferred boundary
        # --------------------------------------------------------------

        #
        # Half before / half after boundary.
        #

        half_preview = max(
            8,
            preview_bytes // 2,
        )

        preview_start = max(
            0,
            boundary_high - half_preview,
        )

        preview_end = min(
            len(data),
            boundary_high + half_preview,
        )

        preview = data[
            preview_start:preview_end
        ]

        if preview:

            console.print()

            console.print(
                "[bold]"
                f"Hexdump around inferred boundary "
                f"({len(preview)} bytes)"
                "[/bold]"
            )

            console.print(
                f"Preview        : "
                f"0x{preview_start:08X} -> "
                f"0x{preview_end:08X}"
            )

            console.print(
                f"Offset       : "
                f"0x{boundary_high:08X}"
            )

            console.print()

            print_hexdump(
                preview,
                preview_start,
            )

            # ----------------------------------------------------------
            # Strings
            # ----------------------------------------------------------

            ascii_strings = (
                extract_ascii_strings(
                    preview
                )
            )

            utf16_strings = (
                extract_utf16le_strings(
                    preview
                )
            )

            console.print()

            console.print(
                "ASCII strings   : "
                + (
                    " | ".join(
                        ascii_strings
                    )
                    if ascii_strings
                    else "-"
                )
            )

            console.print(
                "UTF-16LE strings: "
                + (
                    " | ".join(
                        utf16_strings
                    )
                    if utf16_strings
                    else "-"
                )
            )

    # ------------------------------------------------------------------
    # No candidate
    # ------------------------------------------------------------------

    if not candidates:

        console.print()

        if classification == "CLEAN":

            console.print(
                "[green]"
                "The complete file was not detected. "
                "No boundary narrowing was required."
                "[/green]"
            )

        elif classification == "SCAN_LIMIT_REACHED":

            console.print(
                "[yellow]"
                "The scan limit was reached before a candidate "
                "boundary could be retained."
                "[/yellow]"
            )

        else:

            console.print(
                f"Narrowing result: {classification}"
            )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    detected_count = sum(
        1
        for row in rows
        if row.get(
            "detected"
        )
    )

    clean_count = sum(
        1
        for row in rows
        if not row.get(
            "detected"
        )
    )

    console.print()

    console.print(
        f"Regions scanned : {len(rows)}"
    )

    console.print(
        f"Detected scans  : {detected_count}"
    )

    console.print(
        f"Clean scans     : {clean_count}"
    )

    console.print(
        f"Candidates      : {len(candidates)}"
    )

    console.print(
        f"Classification  : {classification}"
    )


@app.command("inspect-offset")
def inspect_offset_command(
    file: Path = typer.Argument(..., dir_okay=False),
    offset: str = typer.Argument(..., help="File offset, e.g. 0x005C0000 or 6029312"),
    preview_bytes: int = typer.Option(
        DEFAULT_PREVIEW_BYTES,
        "--preview-bytes",
        min=16,
        max=4096,
        help="Context bytes to display from the supplied file offset",
    ),
):
    """Map a known file offset to PE/RVA/VA and display local bytes and strings."""
    file, data, _ = _open_input_or_exit(file)
    try:
        parsed = int(offset, 0)
    except ValueError:
        raise typer.BadParameter("Invalid offset; use hexadecimal (0x...) or decimal")
    if parsed < 0 or parsed >= len(data):
        raise typer.BadParameter("Offset is outside the file")

    result = inspect_offset(file, data, parsed, preview_bytes=preview_bytes)
    preview = result["preview"]
    table = Table(title=f"{__product__} - Offset Context")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("File offset", result.get("offset_hex") or "-")
    table.add_row("Section", result.get("section") or "-")
    table.add_row("RVA", result.get("rva_hex") or "-")
    table.add_row("VA", result.get("va_hex") or "-")
    table.add_row("Image base", result.get("image_base_hex") or "-")
    table.add_row("Region type", result.get("region_type") or "-")
    table.add_row("Preview", f"{preview['start_hex']} -> {preview['end_hex']} ({preview['size']} bytes)")
    console.print(table)
    console.print("[bold]Hexdump[/bold]")
    for line in preview.get("hexdump", []):
        console.print(line)
    console.print("[bold]ASCII strings:[/bold] " + (", ".join(repr(x) for x in preview.get("ascii_strings", [])) or "-"))
    console.print("[bold]UTF-16LE strings:[/bold] " + (", ".join(repr(x) for x in preview.get("utf16le_strings", [])) or "-"))


@app.command("about")
def about():
    """Display product attribution and product information."""
    console.print(f"[bold]{__product__}[/bold]")
    console.print(f"Created by {__author__}")
    console.print("Windows Artifact Analysis and Multi-Engine Scanner")


@app.command("amsi-scan")
def amsi_scan_command(
    file: Path = typer.Argument(..., dir_okay=False),
):
    """Scan a complete file buffer through Windows AMSI."""
    file, _, _ = _open_input_or_exit(file)
    result = amsi_scan_file(file)
    table = Table(title=f"{__product__} - AMSI")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("File", str(file))
    table.add_row("Status", str(result.get("status", "unknown")).upper())
    table.add_row("AMSI result", str(result.get("result_name") or result.get("result", "-")))
    table.add_row("Raw value", str(result.get("result", "-")))
    table.add_row("Bytes", str(result.get("length", "-")))
    console.print(table)


@app.command("script-analyze")
def script_analyze_command(
    file: Path = typer.Argument(..., dir_okay=False),
    context_lines: int = typer.Option(3, "--context-lines", min=0, max=50, help="Context lines shown around structural regions"),
    max_file_size_mib: int = typer.Option(20, "--max-file-size", min=1, max=512, help="Maximum accepted script size in MiB"),
    json_output: bool = typer.Option(False, "--json", help="Print the analysis as JSON in addition to saving the report"),
):
    """Run full-buffer AMSI plus structural analysis for PowerShell/JS/VBS/WSF/text files."""
    file, data, _ = _open_input_or_exit(file)
    if len(data) > max_file_size_mib * 1024 * 1024:
        raise typer.BadParameter(f"File exceeds --max-file-size ({max_file_size_mib} MiB)")
    amsi_result = amsi_scan_file(file)
    result = analyze_script(file, data, amsi_result=amsi_result, context_lines=context_lines)
    console.print(Panel(
        "\n".join([
            f"File            : {file.name}",
            f"Encoding        : {result.get('encoding', {}).get('display', '-')}",
            f"Size            : {result.get('size', 0)} bytes",
            f"Lines           : {result.get('line_count', 0)}",
            f"AMSI             : {str(amsi_result.get('status', 'unknown')).upper()}",
            f"AMSI raw         : {amsi_result.get('result_name') or amsi_result.get('result', '-')}",
            f"Classification   : {result.get('classification', '-')}",
        ]), title="[bold]SigLens - AMSI Analysis[/bold]", border_style="cyan"
    ))
    table = Table(title="Structural regions")
    table.add_column("Lines"); table.add_column("Region"); table.add_column("AST / type")
    table.add_column("Byte offsets"); table.add_column("Indicators", justify="right")
    for region in result.get("regions", []):
        table.add_row(
            f"{region.get('start_line')}-{region.get('end_line')}",
            str(region.get('label') or '-'), str(region.get('ast_type') or '-'),
            f"{region.get('byte_start_hex')} - {region.get('byte_end_hex')}", str(region.get('indicator_score', 0))
        )
    console.print(table)
    candidates = result.get("candidate_regions", [])
    if candidates:
        for idx, candidate in enumerate(candidates, start=1):
            console.print(Panel(
                "\n".join([
                    f"Lines           : {candidate.get('start_line')}-{candidate.get('end_line')}",
                    f"Byte offsets    : {candidate.get('byte_start_hex')} - {candidate.get('byte_end_hex')}",
                    f"AST type        : {candidate.get('ast_type') or '-'}",
                    f"Region          : {candidate.get('label') or '-'}",
                    f"Indicators      : {', '.join(x.get('name','') for x in candidate.get('indicators', [])) or '-'}",
                    f"Classification  : {result.get('classification')}",
                    f"Context lines   : {candidate.get('context', {}).get('start_line')}-{candidate.get('context', {}).get('end_line')}",
                ]), title=f"[yellow]Candidate context #{idx}[/yellow]", border_style="yellow"
            ))
    elif result.get('classification') == 'CONTEXT_DEPENDENT':
        console.print(Panel(
            "The full buffer is detected by AMSI, but no individual structural region can be attributed with confidence.\n"
            "Keep the full script as the best known context and review interactions between blocks.",
            title="[yellow]CONTEXT_DEPENDENT[/yellow]", border_style="yellow"
        ))
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path.cwd() / "reports" / f"script-{file.stem}-{stamp}.json"
    save_json(result, out)
    console.print(f"[green]JSON:[/green] {out}")
    if json_output:
        import json as _json
        console.print(_json.dumps(result, indent=2, ensure_ascii=False, default=str))


@app.command("dissect")
def dissect_command(
    file: Path = typer.Argument(..., dir_okay=False),
):
    """Display PE sections, resources and overlay metadata without modifying the file."""
    file, data, _ = _open_input_or_exit(file)
    result = dissect_pe(file, data)
    if not result.get("is_pe"):
        console.print("[yellow]Input is not a PE file.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"{__product__} - PE Dissection")
    table.add_column("Region")
    table.add_column("Offset")
    table.add_column("RVA")
    table.add_column("Size")
    table.add_column("Entropy")
    table.add_column("SHA256")
    for s in result.get("sections", []):
        table.add_row(
            s["name"],
            hex(s["file_offset"]),
            hex(s["rva"]),
            str(s["size"]),
            str(s["entropy"]),
            s["hashes"]["sha256"][:16] + "...",
        )
    ov = result.get("overlay", {})
    if ov.get("present"):
        table.add_row(
            "[overlay]",
            hex(ov["file_offset"]),
            "-",
            str(ov["size"]),
            str(ov["entropy"]),
            ov["hashes"]["sha256"][:16] + "...",
        )
    console.print(table)
    console.print(f"Resources: {len(result.get('resources', []))}")


@app.command("locate")
def locate(
    file: Path = typer.Argument(..., dir_okay=False),
    offset: str = typer.Argument(..., help="File offset, decimal or hexadecimal (e.g. 0x18A20)"),
    symbol_path: Path | None = typer.Option(None, "--symbol-path", help="Local PDB/symbol directory"),
):
    file, data, _ = _open_input_or_exit(file)
    try:
        value = int(offset, 0)
    except ValueError:
        raise typer.BadParameter("Invalid offset; use 0x18A20 or 100000")
    if value < 0 or value >= len(data):
        raise typer.BadParameter("Offset is outside the file")
    result = correlate_offset(file, value, symbol_path=symbol_path, data=data)
    console.print_json(data=result)


@app.command()
def compare(
    old: Path = typer.Argument(..., dir_okay=False),
    new: Path = typer.Argument(..., dir_okay=False),
):
    try:
        report = compare_files(old, new)
    except Exception as exc:
        console.print(f"[red]Read/compare error :[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(code=2)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = Path.cwd() / "reports" / f"compare-{Path(report['old']['path']).stem}-vs-{Path(report['new']['path']).stem}-{stamp}"
    j = base.with_suffix(".json")
    j.parent.mkdir(parents=True, exist_ok=True)
    save_json(report, j)

    table = Table(title="Build comparison")
    table.add_column("Metric")
    table.add_column("Old")
    table.add_column("New")
    table.add_row("SHA256", report["old"]["hashes"]["sha256"], report["new"]["hashes"]["sha256"])
    table.add_row("Size", str(report["old"]["hashes"]["size"]), str(report["new"]["hashes"]["size"]))
    table.add_row("Entropy", str(report["old"]["entropy"]), str(report["new"]["entropy"]))
    table.add_row("Changed ranges", "", str(len(report["changed_ranges"])))
    console.print(table)
    console.print(f"[green]JSON:[/green] {j}")


@app.command("path-test")
def path_test(file: Path = typer.Argument(..., dir_okay=False)):
    """Diagnose a Windows path and verify SigLens can read it."""
    diag = path_diagnostics(file)
    try:
        p, data, io_meta = read_file_bytes(file)
        diag["read_ok"] = True
        diag["read_size"] = len(data)
        diag["io"] = io_meta
        diag["normalized"] = str(p)
    except Exception as exc:
        diag["read_ok"] = False
        diag["read_error"] = f"{type(exc).__name__}: {exc}"
        diag["io"] = getattr(exc, "siglens_io", None)
    console.print_json(data=diag)
    if not diag["read_ok"]:
        raise typer.Exit(code=2)


@app.command()
def doctor():
    st = defender_status()
    console.print("SigLens: ready")
    console.print(f"Python: {platform.python_version()}")
    console.print(f"Platform: {platform.platform()}")
    console.print("Windows I/O fallback: Python open() -> CreateFileW")
    console.print("DbgHelp/PDB: available on Windows; no automatic symbol download")
    if st.get("status"):
        console.print(f"Defender: {st['status']}")
    else:
        console.print(f"Defender: unavailable or unreadable ({st.get('error') or st.get('stderr','').strip()})")




if __name__ == "__main__":
    app()
