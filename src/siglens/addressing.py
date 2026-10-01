from __future__ import annotations
from pathlib import Path
import pefile
from .fileio import read_file_bytes


def _load_pe(path: Path, data: bytes | None = None, fast_load: bool = True):
    if data is None:
        _, data, _ = read_file_bytes(path)
    return pefile.PE(data=data, fast_load=fast_load)


def file_offset_to_address(path: Path, offset: int, data: bytes | None = None) -> dict:
    result = {
        "file_offset": offset,
        "file_offset_hex": hex(offset),
        "mapped": False,
        "section": None,
        "rva": None,
        "rva_hex": None,
        "va": None,
        "va_hex": None,
        "image_base": None,
    }
    try:
        pe = _load_pe(path, data, True)
    except pefile.PEFormatError:
        return result

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    result["image_base"] = image_base
    try:
        rva = int(pe.get_rva_from_offset(offset))
    except Exception:
        return result

    section_name = None
    for section in pe.sections:
        start = int(section.PointerToRawData)
        end = start + int(section.SizeOfRawData)
        if start <= offset < end:
            section_name = section.Name.rstrip(b"\x00").decode(errors="replace")
            break

    va = image_base + rva
    result.update({
        "mapped": True,
        "section": section_name,
        "rva": rva,
        "rva_hex": hex(rva),
        "va": va,
        "va_hex": hex(va),
    })
    return result


def rva_to_file_offset(path: Path, rva: int, data: bytes | None = None) -> int | None:
    try:
        pe = _load_pe(path, data, True)
        return int(pe.get_offset_from_rva(rva))
    except Exception:
        return None
