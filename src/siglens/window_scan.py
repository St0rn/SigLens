from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import tempfile

from .multiav import scan_engines
from .utils import entropy
from .region_context import map_file_offset, inspect_offset, DEFAULT_PREVIEW_BYTES


MIN_WINDOW_KIB = 1
DEFAULT_WINDOW_KIB = 10
MIN_PREFIX_BYTES = 1
MAX_PREFIX_ATTEMPTS = 3


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixed_windows(
    data: bytes,
    *,
    window_kib: int = DEFAULT_WINDOW_KIB,
    max_windows: int = 2048,
) -> list[dict]:
    """
    Compatibility helper retained for callers that still use fixed windows.

    Note: window_kib is preserved as the existing API name. This helper is not
    used by prefix-boundary narrowing.
    """
    if window_kib < MIN_WINDOW_KIB:
        raise ValueError(
            f"window_kib must be >= {MIN_WINDOW_KIB} B "
            f"(requested: {window_kib} B)"
        )

    window_size = int(window_kib)
    count = (len(data) + window_size - 1) // window_size if data else 0

    if count > max_windows:
        raise ValueError(
            f"window count {count} exceeds max_windows={max_windows}; "
            "increase --max-windows"
        )

    windows = []

    for index, start in enumerate(range(0, len(data), window_size)):
        end = min(len(data), start + window_size)
        blob = data[start:end]

        start_map = map_file_offset(data, start)
        end_map = map_file_offset(data, max(start, end - 1))

        windows.append(
            {
                "index": index,
                "offset": start,
                "offset_hex": f"0x{start:08X}",
                "end": end,
                "end_hex": f"0x{end:08X}",
                "size": len(blob),
                "section": start_map.get("section"),
                "end_section": end_map.get("section"),
                "rva": start_map.get("rva"),
                "rva_hex": start_map.get("rva_hex"),
                "va": start_map.get("va"),
                "va_hex": start_map.get("va_hex"),
                "image_base": start_map.get("image_base"),
                "image_base_hex": start_map.get("image_base_hex"),
                "region_type": start_map.get("region_type"),
                "entropy": round(entropy(blob), 3),
                "sha256": _sha256(blob),
                "data": blob,
            }
        )

    return windows


def window_scan(
    path: Path,
    config_path: Path,
    data: bytes,
    *,
    window_kib: int = DEFAULT_WINDOW_KIB,
    max_windows: int = 2048,
    preview_bytes: int = DEFAULT_PREVIEW_BYTES,
) -> dict:
    """
    Bounded prefix-based AV detection-boundary narrowing.

    Flow:
        1. Scan the complete file.
        2. If DETECTED, scan prefixes data[0:N].
        3. Keep the largest explicitly CLEAN prefix and the smallest explicitly
           DETECTED prefix.
        4. Retry an indeterminate prefix result up to MAX_PREFIX_ATTEMPTS.
        5. Stop when the interval is <= MIN_PREFIX_BYTES, the scan limit is
           reached, or all retries for the same prefix remain indeterminate.

    UNKNOWN / ERROR / UNAVAILABLE are never interpreted as CLEAN.
    The resulting boundary is inferred from repeated scans; it is not a native
    offset supplied by the AV engine.
    """

    minimum_prefix_bytes = MIN_PREFIX_BYTES
    minimum_prefix_kib = minimum_prefix_bytes // 1024

    results: list[dict] = []
    candidates: list[dict] = []
    scan_count = 0

    temp_root = Path(
        tempfile.mkdtemp(
            prefix="siglens-narrow-",
        )
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def format_engine_names(engines: list) -> list[str]:
        names: list[str] = []

        for engine in engines:
            if not isinstance(engine, dict):
                continue

            if str(engine.get("status", "unknown")).lower() == "detected":
                names.append(
                    str(
                        engine.get(
                            "name",
                            "Unknown engine",
                        )
                    )
                )

        return names

    def normalize_engine_states(engines: list) -> dict:
        engine_statuses: list[dict] = []

        for engine in engines:
            if not isinstance(engine, dict):
                continue

            engine_statuses.append(
                {
                    "name": str(engine.get("name", "Unknown engine")),
                    "status": str(engine.get("status", "unknown")).lower(),
                }
            )

        statuses = [row["status"] for row in engine_statuses]

        detected = any(status == "detected" for status in statuses)
        clean = bool(statuses) and all(status == "clean" for status in statuses)
        indeterminate = not detected and not clean

        if detected:
            verdict = "DETECTED"
        elif clean:
            verdict = "CLEAN"
        else:
            verdict = "INDETERMINATE"

        return {
            "engine_statuses": engine_statuses,
            "detected": detected,
            "clean": clean,
            "indeterminate": indeterminate,
            "verdict": verdict,
        }

    def extract_mapping(context: dict | None) -> dict:
        if not isinstance(context, dict):
            return {
                "section": None,
                "rva": None,
                "va": None,
                "image_base": None,
            }

        pe = context.get("pe")
        if not isinstance(pe, dict):
            pe = {}

        section = context.get("section") or pe.get("section")

        rva = (
            context.get("rva")
            if context.get("rva") is not None
            else pe.get("rva")
        )

        va = (
            context.get("va")
            if context.get("va") is not None
            else pe.get("va")
        )

        image_base = (
            context.get("image_base")
            if context.get("image_base") is not None
            else pe.get("image_base")
        )

        return {
            "section": section,
            "rva": rva,
            "va": va,
            "image_base": image_base,
        }

    def get_context(offset: int) -> dict:
        try:
            context = inspect_offset(
                path,
                data,
                int(offset),
                preview_bytes=preview_bytes,
            )

            if isinstance(context, dict):
                return context

            return {
                "file_offset": offset,
            }

        except Exception as exc:
            return {
                "file_offset": offset,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def print_progress(end: int, verdict: str, engine_statuses: list[dict]) -> None:
        status_text = ", ".join(
            f"{row['name']}={row['status']}"
            for row in engine_statuses
        )

        if not status_text:
            status_text = "no-engine-result"

        print(
            f"[SigLens] "
            f"scan={scan_count}/{max_windows} "
            f"prefix=0x{end:08X} "
            f"size={end} "
            f"verdict={verdict} "
            f"engines=[{status_text}]",
            flush=True,
        )

    def scan_region(
        start: int,
        end: int,
        depth: int,
        branch: str,
    ) -> dict | None:
        nonlocal scan_count

        if scan_count >= max_windows:
            return None

        start = max(0, int(start))
        end = min(len(data), int(end))

        if end <= start:
            return None

        blob = data[start:end]
        scan_count += 1

        temp_file = (
            temp_root
            / f"region_{scan_count:05d}_{start:08X}_{end:08X}.bin"
        )

        try:
            temp_file.write_bytes(blob)
            engine_result = scan_engines(temp_file, config_path)
            engines = engine_result.get("results", [])
            summary = engine_result.get("summary", {})

        except Exception as exc:
            engines = []
            summary = {
                "error": f"{type(exc).__name__}: {exc}",
            }

        state = normalize_engine_states(engines)
        detected_by = format_engine_names(engines)

        try:
            region_entropy = entropy(blob)
        except Exception:
            region_entropy = None

        context = get_context(start)
        mapping = extract_mapping(context)

        result = {
            "index": scan_count - 1,
            "offset": start,
            "start": start,
            "end": end,
            "end_offset": end,
            "size": end - start,
            "depth": depth,
            "branch": branch,
            "entropy": region_entropy,
            "section": mapping.get("section"),
            "rva": mapping.get("rva"),
            "va": mapping.get("va"),
            "image_base": mapping.get("image_base"),
            "context": context,
            "engines": engines,
            "summary": summary,
            "engine_statuses": state["engine_statuses"],
            "detected": state["detected"],
            "clean": state["clean"],
            "indeterminate": state["indeterminate"],
            "verdict": state["verdict"],
            "detected_by": detected_by,
            "classification": state["verdict"],
        }

        results.append(result)
        print_progress(end, state["verdict"], state["engine_statuses"])

        return result

    def scan_prefix(
        end: int,
        depth: int,
    ) -> dict | None:
        nonlocal scan_count

        if scan_count >= max_windows:
            return None

        end = min(
            len(data),
            max(1, int(end)),
        )

        blob = data[:end]
        scan_count += 1

        temp_file = (
            temp_root
            / f"prefix_{scan_count:05d}_00000000_{end:08X}.bin"
        )

        try:
            temp_file.write_bytes(blob)

        except Exception as exc:
            result = {
                "index": scan_count - 1,
                "offset": 0,
                "start": 0,
                "end": end,
                "end_offset": end,
                "size": end,
                "depth": depth,
                "branch": "prefix",
                "entropy": None,
                "section": None,
                "rva": None,
                "va": None,
                "image_base": None,
                "context": {},
                "engines": [],
                "summary": {
                    "error": f"{type(exc).__name__}: {exc}",
                },
                "engine_statuses": [],
                "detected": False,
                "clean": False,
                "indeterminate": True,
                "verdict": "INDETERMINATE",
                "detected_by": [],
                "classification": "INDETERMINATE",
            }

            results.append(result)
            print_progress(end, "INDETERMINATE", [])
            return result

        try:
            engine_result = scan_engines(
                temp_file,
                config_path,
            )

            engines = engine_result.get("results", [])
            summary = engine_result.get("summary", {})

        except Exception as exc:
            engines = []
            summary = {
                "error": f"{type(exc).__name__}: {exc}",
            }

        state = normalize_engine_states(engines)
        detected_by = format_engine_names(engines)

        try:
            region_entropy = entropy(blob)
        except Exception:
            region_entropy = None

        boundary_offset = max(0, end - 1)
        context = get_context(boundary_offset)
        mapping = extract_mapping(context)

        result = {
            "index": scan_count - 1,
            "offset": 0,
            "start": 0,
            "end": end,
            "end_offset": end,
            "size": end,
            "depth": depth,
            "branch": "prefix",
            "entropy": region_entropy,
            "boundary_offset": boundary_offset,
            "section": mapping.get("section"),
            "rva": mapping.get("rva"),
            "va": mapping.get("va"),
            "image_base": mapping.get("image_base"),
            "context": context,
            "engines": engines,
            "summary": summary,
            "engine_statuses": state["engine_statuses"],
            "detected": state["detected"],
            "clean": state["clean"],
            "indeterminate": state["indeterminate"],
            "verdict": state["verdict"],
            "detected_by": detected_by,
            "classification": state["verdict"],
        }

        results.append(result)
        print_progress(end, state["verdict"], state["engine_statuses"])

        return result

    def narrow(
        parent: dict,
        depth: int,
    ) -> None:
        nonlocal scan_count

        low = 0
        high = len(data)

        best_detected = parent
        best_clean: dict | None = None

        while high - low > minimum_prefix_bytes:
            if scan_count >= max_windows:
                candidate = dict(best_detected)
                candidate["classification"] = "SCAN_LIMIT_REACHED"
                candidate["reason"] = (
                    "Maximum number of AV scans reached during "
                    "prefix boundary narrowing."
                )
                candidate["boundary_low"] = low
                candidate["boundary_high"] = high
                candidate["boundary_size"] = high - low
                candidate["last_clean_prefix"] = (
                    best_clean.get("end") if best_clean is not None else None
                )
                candidate["first_detected_prefix"] = best_detected.get("end")
                candidates.append(candidate)
                return

            midpoint = low + ((high - low) // 2)

            if midpoint <= low or midpoint >= high:
                break

            # Retry the same midpoint when the AV engine returns an
            # indeterminate result. A retry that becomes DETECTED or CLEAN
            # is accepted; INDETERMINATE is never treated as CLEAN.
            prefix = None
            attempts = 0

            while attempts < MAX_PREFIX_ATTEMPTS:
                if scan_count >= max_windows:
                    break

                attempts += 1

                current = scan_prefix(
                    midpoint,
                    depth + 1,
                )

                if current is None:
                    continue

                prefix = current

                if current.get("detected") or current.get("clean"):
                    break

                print(
                    f"[SigLens] retry={attempts}/{MAX_PREFIX_ATTEMPTS} "
                    f"prefix=0x{midpoint:08X} verdict=INDETERMINATE",
                    flush=True,
                )

            if prefix is None:
                candidate = dict(best_detected)
                candidate["classification"] = "SCAN_LIMIT_REACHED"
                candidate["reason"] = "Prefix scan could not be performed."
                candidate["boundary_low"] = low
                candidate["boundary_high"] = high
                candidate["boundary_size"] = high - low
                candidate["last_clean_prefix"] = (
                    best_clean.get("end") if best_clean is not None else None
                )
                candidate["first_detected_prefix"] = best_detected.get("end")
                candidates.append(candidate)
                return

            if prefix.get("detected"):
                high = midpoint
                best_detected = prefix
                continue

            if prefix.get("clean"):
                low = midpoint
                best_clean = prefix
                continue

            candidate = dict(best_detected)
            candidate["classification"] = "ENGINE_RESULT_INDETERMINATE"
            candidate["reason"] = (
                "Prefix narrowing stopped because the AV engine remained "
                f"indeterminate after {attempts} attempt(s). The result was "
                "not interpreted as CLEAN."
            )
            candidate["boundary_low"] = low
            candidate["boundary_high"] = high
            candidate["boundary_size"] = high - low
            candidate["last_clean_prefix"] = (
                best_clean.get("end") if best_clean is not None else None
            )
            candidate["first_detected_prefix"] = best_detected.get("end")
            candidate["indeterminate_attempts"] = attempts
            candidates.append(candidate)
            return

        # A meaningful CLEAN -> DETECTED boundary requires at least one
        # explicitly CLEAN prefix and one explicitly DETECTED prefix.
        if best_clean is None:
            candidate = dict(best_detected)
            candidate["classification"] = "BOUNDARY_NOT_ESTABLISHED"
            candidate["reason"] = (
                "No tested prefix was explicitly classified CLEAN, so a "
                "CLEAN-to-DETECTED transition could not be established."
            )
            candidate["boundary_low"] = None
            candidate["boundary_high"] = high
            candidate["boundary_size"] = None
            candidate["last_clean_prefix"] = None
            candidate["first_detected_prefix"] = best_detected.get("end")
            candidates.append(candidate)
            return

        if high <= low:
            candidate = dict(best_detected)
            candidate["classification"] = "BOUNDARY_NOT_ESTABLISHED"
            candidate["reason"] = (
                "A valid CLEAN-to-DETECTED boundary could not be established."
            )
            candidate["boundary_low"] = low
            candidate["boundary_high"] = high
            candidate["boundary_size"] = max(0, high - low)
            candidate["last_clean_prefix"] = best_clean.get("end")
            candidate["first_detected_prefix"] = best_detected.get("end")
            candidates.append(candidate)
            return

        candidate = dict(best_detected)
        candidate["classification"] = "CANDIDATE_REGION"
        candidate["reason"] = (
            "Prefix narrowing identified a bounded CLEAN-to-DETECTED "
            "transition interval."
        )

        candidate["boundary_low"] = low
        candidate["boundary_high"] = high
        candidate["boundary_size"] = high - low
        candidate["last_clean_prefix"] = best_clean.get("end")
        candidate["first_detected_prefix"] = best_detected.get("end")

        # Compatibility with the CLI renderer: represent the candidate as the
        # transition interval, not the whole detected prefix.
        candidate["start"] = low
        candidate["offset"] = low
        candidate["end"] = high
        candidate["end_offset"] = high
        candidate["size"] = high - low

        # high is a prefix length, therefore high - 1 is the last byte included
        # in the smallest known DETECTED prefix.
        boundary_offset = max(
            0,
            min(
                len(data) - 1,
                high - 1,
            ),
        )

        candidate["boundary_offset"] = boundary_offset
        candidate["inferred_offset"] = boundary_offset

        context = get_context(boundary_offset)
        mapping = extract_mapping(context)

        candidate["context"] = context
        candidate["section"] = mapping.get("section")
        candidate["rva"] = mapping.get("rva")
        candidate["va"] = mapping.get("va")
        candidate["image_base"] = mapping.get("image_base")

        candidates.append(candidate)

    # ------------------------------------------------------------------
    # MAIN
    # ------------------------------------------------------------------

    try:
        if not data:
            return {
                "mode": "prefix_boundary_narrowing",
                "display_title": "SigLens - Detection Boundary Narrowing",
                "classification": "EMPTY_FILE",
                "window_kib": window_kib,
                "window_bytes": window_kib,
                "minimum_window_kib": minimum_prefix_kib,
                "minimum_window_bytes": minimum_prefix_bytes,
                "context_preview_bytes": preview_bytes,
                "file_size": 0,
                "scan_count": 0,
                "max_scans": max_windows,
                "window_count": 0,
                "detected_window_count": 0,
                "clean_window_count": 0,
                "indeterminate_window_count": 0,
                "detected_windows": [],
                "clean_windows": [],
                "indeterminate_windows": [],
                "candidate_count": 0,
                "candidates": [],
                "windows": [],
                "note": "The input file is empty.",
            }

        root = scan_region(
            0,
            len(data),
            0,
            "root",
        )

        if root is None:
            return {
                "mode": "prefix_boundary_narrowing",
                "display_title": "SigLens - Detection Boundary Narrowing",
                "classification": "SCAN_LIMIT_REACHED",
                "window_kib": window_kib,
                "window_bytes": window_kib,
                "minimum_window_kib": minimum_prefix_kib,
                "minimum_window_bytes": minimum_prefix_bytes,
                "context_preview_bytes": preview_bytes,
                "file_size": len(data),
                "scan_count": scan_count,
                "max_scans": max_windows,
                "window_count": len(results),
                "detected_window_count": 0,
                "clean_window_count": 0,
                "indeterminate_window_count": 0,
                "detected_windows": [],
                "clean_windows": [],
                "indeterminate_windows": [],
                "candidate_count": 0,
                "candidates": [],
                "windows": results,
                "note": "The initial full-file scan could not be performed.",
            }

        if root.get("indeterminate"):
            candidates.append(
                {
                    **root,
                    "classification": "ENGINE_RESULT_INDETERMINATE",
                    "reason": (
                        "The initial full-file scan returned an indeterminate "
                        "engine result. Narrowing was not started."
                    ),
                }
            )

        elif root.get("clean"):
            return {
                "mode": "prefix_boundary_narrowing",
                "display_title": "SigLens - Detection Boundary Narrowing",
                "classification": "CLEAN",
                "window_kib": window_kib,
                "window_bytes": window_kib,
                "minimum_window_kib": minimum_prefix_kib,
                "minimum_window_bytes": minimum_prefix_bytes,
                "context_preview_bytes": preview_bytes,
                "file_size": len(data),
                "scan_count": scan_count,
                "max_scans": max_windows,
                "window_count": len(results),
                "detected_window_count": 0,
                "clean_window_count": 1,
                "indeterminate_window_count": 0,
                "detected_windows": [],
                "clean_windows": [root["index"]],
                "indeterminate_windows": [],
                "candidate_count": 0,
                "candidates": [],
                "windows": results,
                "note": (
                    "The complete input was explicitly classified CLEAN by "
                    "the configured engine set."
                ),
            }

        elif root.get("detected"):
            narrow(
                root,
                0,
            )

        else:
            candidates.append(
                {
                    **root,
                    "classification": "ENGINE_RESULT_INDETERMINATE",
                    "reason": (
                        "The initial full-file scan did not produce a reliable "
                        "CLEAN or DETECTED verdict."
                    ),
                }
            )

    finally:
        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )

    # ------------------------------------------------------------------
    # FINAL RESULT
    # ------------------------------------------------------------------

    detected_windows = [
        row["index"]
        for row in results
        if row.get("detected")
    ]

    clean_windows = [
        row["index"]
        for row in results
        if row.get("clean")
    ]

    indeterminate_windows = [
        row["index"]
        for row in results
        if row.get("indeterminate")
    ]

    classifications = {
        candidate.get("classification")
        for candidate in candidates
    }

    if not candidates:
        overall_classification = "DETECTED"
    elif len(candidates) > 1:
        overall_classification = "MULTIPLE_CANDIDATE_REGIONS"
    elif "ENGINE_RESULT_INDETERMINATE" in classifications:
        overall_classification = "ENGINE_RESULT_INDETERMINATE"
    elif "SCAN_LIMIT_REACHED" in classifications:
        overall_classification = "SCAN_LIMIT_REACHED"
    elif "BOUNDARY_NOT_ESTABLISHED" in classifications:
        overall_classification = "BOUNDARY_NOT_ESTABLISHED"
    else:
        overall_classification = candidates[0].get(
            "classification",
            "CANDIDATE_REGION",
        )

    return {
        "mode": "prefix_boundary_narrowing",
        "display_title": "SigLens - Detection Boundary Narrowing",
        "classification": overall_classification,

        # Existing API / renderer compatibility.
        "window_kib": window_kib,
        "window_bytes": window_kib,
        "minimum_window_kib": minimum_prefix_kib,
        "minimum_window_bytes": minimum_prefix_bytes,
        "context_preview_bytes": preview_bytes,

        "file_size": len(data),
        "scan_count": scan_count,
        "max_scans": max_windows,
        "window_count": len(results),
        "detected_window_count": len(detected_windows),
        "clean_window_count": len(clean_windows),
        "indeterminate_window_count": len(indeterminate_windows),
        "detected_windows": detected_windows,
        "clean_windows": clean_windows,
        "indeterminate_windows": indeterminate_windows,
        "windows": results,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "note": (
            "The complete file is scanned first. If DETECTED, SigLens scans "
            "prefixes of the original file and narrows the interval between "
            "the largest prefix explicitly classified CLEAN and the smallest "
            "prefix explicitly classified DETECTED. UNKNOWN, ERROR and "
            "UNAVAILABLE results are treated as indeterminate and are never "
            "interpreted as CLEAN. The resulting boundary is inferred from "
            "repeated scans and is not a native byte offset supplied by the "
            "AV engine."
        ),
    }
