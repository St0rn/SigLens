from __future__ import annotations
from pathlib import Path
import hashlib
import pefile
from .utils import entropy

def _hashes(data: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }

def dissect_pe(path: Path, data: bytes | None = None) -> dict:
    data = data if data is not None else path.read_bytes()
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return {"is_pe": False, "file_size": len(data)}

    items = []
    last_raw_end = 0
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        start = int(s.PointerToRawData)
        size = int(s.SizeOfRawData)
        end = min(len(data), start + size)
        blob = data[start:end] if 0 <= start < len(data) else b""
        last_raw_end = max(last_raw_end, end)
        items.append({
            "kind": "section",
            "name": name,
            "file_offset": start,
            "file_end": end,
            "size": len(blob),
            "rva": int(s.VirtualAddress),
            "virtual_size": int(s.Misc_VirtualSize),
            "entropy": round(entropy(blob), 3),
            "hashes": _hashes(blob),
            "characteristics": int(s.Characteristics),
        })

    resources = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = str(type_entry.name or type_entry.struct.Id)
                if not hasattr(type_entry, "directory"):
                    continue
                for name_entry in type_entry.directory.entries:
                    name = str(name_entry.name or name_entry.struct.Id)
                    if not hasattr(name_entry, "directory"):
                        continue
                    for lang_entry in name_entry.directory.entries:
                        d = lang_entry.data.struct
                        offset = pe.get_offset_from_rva(d.OffsetToData)
                        blob = data[offset:offset + d.Size]
                        resources.append({
                            "type": type_name,
                            "name": name,
                            "lang": int(lang_entry.struct.Id),
                            "file_offset": int(offset),
                            "size": int(d.Size),
                            "entropy": round(entropy(blob), 3),
                            "hashes": _hashes(blob),
                        })
    except Exception as exc:
        resources.append({"error": str(exc)})

    overlay = b""
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is not None and 0 <= overlay_offset < len(data):
        overlay = data[overlay_offset:]

    return {
        "is_pe": True,
        "file_size": len(data),
        "sections": items,
        "resources": resources,
        "overlay": {
            "present": bool(overlay),
            "file_offset": int(overlay_offset) if overlay_offset is not None else None,
            "size": len(overlay),
            "entropy": round(entropy(overlay), 3) if overlay else 0.0,
            "hashes": _hashes(overlay) if overlay else None,
        },
    }
