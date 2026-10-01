from __future__ import annotations
from pathlib import Path
import pefile
from .fileio import read_file_bytes


def _runtime_function_ranges(pe: pefile.PE) -> list[dict]:
    """Return x64/ARM64 runtime function ranges from the PE exception directory.

    On x64 these entries correspond to function ranges used for unwind metadata and are
    substantially more reliable than guessing boundaries from disassembly bytes.
    """
    ranges: list[dict] = []
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
        )
    except Exception:
        return ranges

    entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None) or []
    for entry in entries:
        st = getattr(entry, "struct", None)
        if st is None:
            continue
        begin = getattr(st, "BeginAddress", None)
        end = getattr(st, "EndAddress", None)
        unwind = getattr(st, "UnwindData", None)
        if begin is None or end is None:
            continue
        begin, end = int(begin), int(end)
        if end <= begin:
            continue
        ranges.append({
            "begin_rva": begin,
            "end_rva": end,
            "size": end - begin,
            "unwind_rva": int(unwind) if unwind is not None else None,
        })
    ranges.sort(key=lambda x: x["begin_rva"])
    return ranges


def resolve_runtime_function(path: Path, rva: int, data: bytes | None = None) -> dict:
    out = {
        "resolved": False,
        "method": None,
        "confidence": "none",
        "begin_rva": None,
        "end_rva": None,
        "begin_file_offset": None,
        "size": None,
        "label": None,
    }
    try:
        if data is None:
            _, data, _ = read_file_bytes(path)
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return out

    # Preferred: exact containment in the platform's runtime-function table.
    for item in _runtime_function_ranges(pe):
        if item["begin_rva"] <= rva < item["end_rva"]:
            try:
                raw = int(pe.get_offset_from_rva(item["begin_rva"]))
            except Exception:
                raw = None
            out.update({
                "resolved": True,
                "method": "exception_directory_runtime_function",
                "confidence": "high",
                "begin_rva": item["begin_rva"],
                "end_rva": item["end_rva"],
                "begin_file_offset": raw,
                "size": item["size"],
                "label": f"sub_{int(pe.OPTIONAL_HEADER.ImageBase) + item['begin_rva']:X}",
            })
            return out

    # Secondary: exported symbol range approximation.
    exports = []
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        for sym in getattr(pe, "DIRECTORY_ENTRY_EXPORT", []).symbols:
            exports.append((int(sym.address), sym.name.decode(errors="replace") if sym.name else None))
    except Exception:
        pass
    exports.sort()
    previous = None
    following = None
    for addr, name in exports:
        if addr <= rva:
            previous = (addr, name)
        elif addr > rva:
            following = (addr, name)
            break
    if previous:
        begin, name = previous
        end = following[0] if following else None
        # Avoid pretending an arbitrary distant export is the containing function.
        if rva - begin <= 0x10000:
            try:
                raw = int(pe.get_offset_from_rva(begin))
            except Exception:
                raw = None
            out.update({
                "resolved": True,
                "method": "nearest_preceding_export",
                "confidence": "low",
                "begin_rva": begin,
                "end_rva": end,
                "begin_file_offset": raw,
                "size": (end - begin) if end else None,
                "label": name or f"export_{begin:X}",
            })
    return out
