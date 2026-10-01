from __future__ import annotations

import string
from pathlib import Path
import pefile
from .strings import extract_strings

DEFAULT_PREVIEW_BYTES = 256


def _printable(byte: int) -> str:
    ch = chr(byte)
    return ch if ch in string.printable and ch not in "\r\n\t\x0b\x0c" else "."


def hexdump(data: bytes, base_offset: int = 0, width: int = 16) -> list[str]:
    lines: list[str] = []
    for rel in range(0, len(data), width):
        chunk = data[rel:rel + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(_printable(b) for b in chunk)
        lines.append(f"{base_offset + rel:08x}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|")
    return lines


def _layout(data: bytes) -> dict:
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return {"is_pe": False, "image_base": None, "size_of_headers": 0, "sections": [], "overlay_offset": None}

    sections = []
    for sec in pe.sections:
        raw_start = int(sec.PointerToRawData)
        raw_size = int(sec.SizeOfRawData)
        raw_end = min(len(data), raw_start + raw_size)
        sections.append({
            "name": sec.Name.rstrip(b"\\x00").decode(errors="replace") or "<unnamed>",
            "raw_start": raw_start,
            "raw_end": raw_end,
            "rva_start": int(sec.VirtualAddress),
        })
    return {
        "is_pe": True,
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "size_of_headers": int(pe.OPTIONAL_HEADER.SizeOfHeaders),
        "sections": sections,
        "overlay_offset": pe.get_overlay_data_start_offset(),
    }


def map_file_offset(data: bytes, offset: int) -> dict:
    if offset < 0 or offset >= len(data):
        raise ValueError(f"offset 0x{offset:x} is outside the file (size=0x{len(data):x})")

    layout = _layout(data)
    result = {
        "offset": offset,
        "offset_hex": f"0x{offset:08X}",
        "section": None,
        "rva": None,
        "rva_hex": None,
        "va": None,
        "va_hex": None,
        "image_base": layout.get("image_base"),
        "image_base_hex": f"0x{layout['image_base']:X}" if layout.get("image_base") is not None else None,
        "region_type": "raw",
    }
    if not layout["is_pe"]:
        return result

    if offset < layout["size_of_headers"]:
        rva = offset
        va = layout["image_base"] + rva
        result.update({"section":"<PE_HEADERS>","rva":rva,"rva_hex":f"0x{rva:08X}","va":va,"va_hex":f"0x{va:X}","region_type":"headers"})
        return result

    for sec in layout["sections"]:
        if sec["raw_start"] <= offset < sec["raw_end"]:
            delta = offset - sec["raw_start"]
            rva = sec["rva_start"] + delta
            va = layout["image_base"] + rva
            result.update({"section":sec["name"],"rva":rva,"rva_hex":f"0x{rva:08X}","va":va,"va_hex":f"0x{va:X}","region_type":"section"})
            return result

    overlay = layout.get("overlay_offset")
    if overlay is not None and offset >= int(overlay):
        result.update({"section":"<OVERLAY>","region_type":"overlay"})
    return result


def inspect_offset(path: Path, data: bytes, offset: int, *, preview_bytes: int = DEFAULT_PREVIEW_BYTES) -> dict:
    mapping = map_file_offset(data, offset)
    preview_bytes = max(1, int(preview_bytes))
    end = min(len(data), offset + preview_bytes)
    blob = data[offset:end]
    strings = extract_strings(blob, 200)
    return {
        **mapping,
        "preview": {
            "start": offset,
            "start_hex": f"0x{offset:08X}",
            "end": end,
            "end_hex": f"0x{end:08X}",
            "size": len(blob),
            "requested_size": preview_bytes,
            "hexdump": hexdump(blob, base_offset=offset),
            "ascii_strings": strings.get("ascii", []),
            "utf16le_strings": strings.get("utf16le", []),
        },
    }
