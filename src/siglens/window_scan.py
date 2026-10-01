from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import tempfile

from .multiav import scan_engines
from .utils import entropy
from .region_context import map_file_offset, inspect_offset, DEFAULT_PREVIEW_BYTES

MIN_WINDOW_KIB = 256
DEFAULT_WINDOW_KIB = 256


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixed_windows(data: bytes, *, window_kib: int = DEFAULT_WINDOW_KIB, max_windows: int = 2048) -> list[dict]:
    if window_kib < MIN_WINDOW_KIB:
        raise ValueError(f"window_kib must be >= {MIN_WINDOW_KIB} KiB (requested: {window_kib} KiB)")
    window_size = int(window_kib) * 1024
    count = (len(data) + window_size - 1) // window_size if data else 0
    if count > max_windows:
        raise ValueError(f"window count {count} exceeds max_windows={max_windows}; increase --window-size or --max-windows")

    windows = []
    for index, start in enumerate(range(0, len(data), window_size)):
        end = min(len(data), start + window_size)
        blob = data[start:end]
        start_map = map_file_offset(data, start)
        end_map = map_file_offset(data, max(start, end - 1))
        windows.append({
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
        })
    return windows


def window_scan(path: Path, config_path: Path, data: bytes, *, window_kib: int = DEFAULT_WINDOW_KIB, max_windows: int = 2048, preview_bytes: int = DEFAULT_PREVIEW_BYTES) -> dict:
    windows = fixed_windows(data, window_kib=window_kib, max_windows=max_windows)
    results = []
    temp_root = Path(tempfile.mkdtemp(prefix="siglens-windows-"))
    try:
        for window in windows:
            temp_file = temp_root / f"window_{window['index']:05d}.bin"
            temp_file.write_bytes(window["data"])
            engine_result = scan_engines(temp_file, config_path)
            public = {k:v for k,v in window.items() if k != "data"}
            public["engines"] = engine_result["results"]
            public["summary"] = engine_result["summary"]
            public["detected"] = any(e.get("status") == "detected" for e in public["engines"])
            if public["detected"]:
                public["context"] = inspect_offset(path, data, int(window["offset"]), preview_bytes=preview_bytes)
            results.append(public)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    detected_windows = [row["index"] for row in results if row.get("detected")]
    return {
        "mode": "fixed_non_overlapping_windows",
        "window_kib": window_kib,
        "window_bytes": window_kib * 1024,
        "minimum_window_kib": MIN_WINDOW_KIB,
        "context_preview_bytes": preview_bytes,
        "file_size": len(data),
        "window_count": len(results),
        "detected_window_count": len(detected_windows),
        "detected_windows": detected_windows,
        "windows": results,
        "note": (
            "Fixed, non-overlapping windows only. The reported offset is the original window start. "
            "PE/RVA/VA mapping and the 256-byte preview are anchored to that fixed boundary. "
            "No recursive or adaptive refinement is performed."
        ),
    }
