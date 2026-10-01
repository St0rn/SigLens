from __future__ import annotations
from pathlib import Path
import pefile
from .utils import entropy
from .fileio import read_file_bytes

SENSITIVE_IMPORT_HINTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtWriteVirtualMemory", "CreateProcess", "CreateProcessW",
    "LoadLibrary", "GetProcAddress", "WinHttpOpen", "InternetOpen",
}


def analyze_pe(path: Path, data: bytes | None = None) -> dict:
    out = {"is_pe": False}
    try:
        if data is None:
            _, data, _ = read_file_bytes(path)
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return out

    out["is_pe"] = True
    out["machine"] = hex(pe.FILE_HEADER.Machine)
    out["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    out["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    out["entry_point_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        raw = s.get_data()
        sections.append({
            "name": name,
            "virtual_address": hex(s.VirtualAddress),
            "raw_offset": hex(s.PointerToRawData),
            "raw_size": int(s.SizeOfRawData),
            "virtual_size": int(s.Misc_VirtualSize),
            "entropy": round(entropy(raw), 3),
            "characteristics": hex(s.Characteristics),
        })
    out["sections"] = sections

    imports = []
    sensitive = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            funcs = []
            for imp in entry.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
                funcs.append(name)
                if name in SENSITIVE_IMPORT_HINTS:
                    sensitive.append(f"{dll}!{name}")
            imports.append({"dll": dll, "functions": funcs})
    out["imports"] = imports
    out["sensitive_imports"] = sensitive

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name": sym.name.decode(errors="replace") if sym.name else None,
                "ordinal": sym.ordinal,
                "address": hex(sym.address),
            })
    out["exports"] = exports
    return out
