from __future__ import annotations

from pathlib import Path
import shutil
import tempfile

import pefile

from .multiav import scan_engines
from .utils import entropy


def _regions(data: bytes) -> list[dict]:
    pe = pefile.PE(data=data, fast_load=False)
    regions = []

    for section in pe.sections:
        start = int(section.PointerToRawData)
        size = int(section.SizeOfRawData)
        end = min(len(data), start + size)
        if size <= 0 or start < 0 or start >= len(data):
            continue
        blob = data[start:end]
        regions.append(
            {
                "kind": "section",
                "name": section.Name.rstrip(b"\x00").decode(errors="replace") or "<unnamed>",
                "offset": start,
                "end": end,
                "rva": int(section.VirtualAddress),
                "size": len(blob),
                "entropy": round(entropy(blob), 3),
                "data": blob,
            }
        )

    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is not None and overlay_offset < len(data):
        blob = data[overlay_offset:]
        if blob:
            regions.append(
                {
                    "kind": "overlay",
                    "name": "[overlay]",
                    "offset": int(overlay_offset),
                    "end": len(data),
                    "rva": None,
                    "size": len(blob),
                    "entropy": round(entropy(blob), 3),
                    "data": blob,
                }
            )

    return regions


def component_scan(path: Path, config_path: Path, data: bytes, *, max_regions: int = 32) -> dict:
    try:
        regions = _regions(data)
    except pefile.PEFormatError:
        return {"is_pe": False, "regions": [], "error": "Input is not a PE file."}

    results = []
    temp_root = Path(tempfile.mkdtemp(prefix="siglens-regions-"))
    try:
        for index, region in enumerate(regions[:max_regions]):
            safe_name = "".join(
                char if char.isalnum() or char in "._-" else "_"
                for char in region["name"]
            )
            temp_file = temp_root / f"{index:02d}_{safe_name}.bin"
            temp_file.write_bytes(region["data"])

            engine_result = scan_engines(temp_file, config_path)
            public = {key: value for key, value in region.items() if key != "data"}
            public["engines"] = engine_result["results"]
            public["summary"] = engine_result["summary"]
            results.append(public)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    return {
        "is_pe": True,
        "mode": "fixed_pe_regions",
        "regions": results,
        "note": "Coarse PE-region attribution only. Regions are not recursively split or bisected.",
    }
