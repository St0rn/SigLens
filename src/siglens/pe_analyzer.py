from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import struct
import uuid

import pefile

from .fileio import read_file_bytes
from .utils import entropy


SENSITIVE_IMPORT_HINTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtWriteVirtualMemory", "CreateProcess", "CreateProcessW",
    "LoadLibrary", "GetProcAddress", "WinHttpOpen", "InternetOpen",
}

IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_DLL = 0x2000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

DLL_CHARACTERISTICS = {
    "high_entropy_va": 0x0020,
    "aslr": 0x0040,
    "force_integrity": 0x0080,
    "dep": 0x0100,
    "no_seh": 0x0400,
    "app_container": 0x1000,
    "cfg": 0x4000,
}

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}


def _directory(pe: pefile.PE, name: str):
    index = pefile.DIRECTORY_ENTRY.get(name)
    directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
    if index is None or index >= len(directories):
        return None
    return directories[index]


def _section_name(section) -> str:
    return section.Name.rstrip(b"\x00").decode(errors="replace")


def _section_for_rva(pe: pefile.PE, rva: int):
    for section in pe.sections:
        start = int(section.VirtualAddress)
        size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva < start + size:
            return section
    return None


def _timestamp(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _debug_entries(pe: pefile.PE, data: bytes) -> list[dict]:
    entries = []
    for item in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        header = item.struct
        offset = int(getattr(header, "PointerToRawData", 0))
        size = int(getattr(header, "SizeOfData", 0))
        blob = data[offset:offset + size] if 0 <= offset < len(data) else b""
        row = {
            "type": int(getattr(header, "Type", 0)),
            "file_offset": offset,
            "size": size,
            "timestamp": int(getattr(header, "TimeDateStamp", 0)),
        }
        if blob.startswith(b"RSDS") and len(blob) >= 24:
            row["format"] = "RSDS"
            row["pdb_guid"] = str(uuid.UUID(bytes_le=blob[4:20])).upper()
            row["pdb_age"] = struct.unpack_from("<I", blob, 20)[0]
            row["pdb_path"] = blob[24:].split(b"\x00", 1)[0].decode(errors="replace")
        elif blob.startswith(b"NB10") and len(blob) >= 16:
            row["format"] = "NB10"
            row["pdb_age"] = struct.unpack_from("<I", blob, 12)[0]
            row["pdb_path"] = blob[16:].split(b"\x00", 1)[0].decode(errors="replace")
        entries.append(row)
    return entries


def _authenticode(pe: pefile.PE, data: bytes) -> dict:
    directory = _directory(pe, "IMAGE_DIRECTORY_ENTRY_SECURITY")
    offset = int(getattr(directory, "VirtualAddress", 0)) if directory else 0
    size = int(getattr(directory, "Size", 0)) if directory else 0
    present = offset > 0 and size > 0
    result = {
        "present": present,
        "file_offset": offset if present else None,
        "size": size,
        "bounds_valid": (offset + size <= len(data)) if present else None,
        "trust_verification_performed": False,
        "trust_status": "not_checked",
        "note": "Certificate-table presence does not verify signer identity or trust.",
    }
    if present and offset + 8 <= len(data):
        length, revision, certificate_type = struct.unpack_from("<IHH", data, offset)
        result.update({
            "certificate_length": length,
            "revision": hex(revision),
            "certificate_type": hex(certificate_type),
            "certificate_bounds_valid": 8 <= length <= size and offset + length <= len(data),
        })
    return result


def _tls_callbacks(pe: pefile.PE) -> dict:
    entry = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if entry is None:
        return {"present": False, "callback_array_va": None, "callbacks": [], "truncated": False}

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    callback_array_va = int(getattr(entry.struct, "AddressOfCallBacks", 0))
    pointer_size = 8 if int(getattr(pe.OPTIONAL_HEADER, "Magic", 0)) == 0x20B else 4
    callbacks = []
    if callback_array_va >= image_base:
        rva = callback_array_va - image_base
        getter = pe.get_qword_at_rva if pointer_size == 8 else pe.get_dword_at_rva
        for index in range(64):
            try:
                value = getter(rva + index * pointer_size)
            except Exception:
                break
            if not value:
                break
            value = int(value)
            callbacks.append({
                "va": value,
                "va_hex": hex(value),
                "rva": value - image_base if value >= image_base else None,
            })
    return {
        "present": True,
        "callback_array_va": callback_array_va or None,
        "callbacks": callbacks,
        "truncated": len(callbacks) == 64,
    }


def _load_config(pe: pefile.PE) -> dict:
    entry = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if entry is None:
        return {"present": False}
    config = entry.struct
    fields = {
        "present": True,
        "size": int(getattr(config, "Size", 0)),
        "security_cookie_va": int(getattr(config, "SecurityCookie", 0)) or None,
        "guard_flags": int(getattr(config, "GuardFlags", 0)),
        "guard_cf_function_count": int(getattr(config, "GuardCFFunctionCount", 0)),
        "seh_handler_count": int(getattr(config, "SEHandlerCount", 0)),
    }
    fields["guard_flags_hex"] = hex(fields["guard_flags"])
    return fields


def _append_finding(findings: list[dict], finding_id: str, severity: str, title: str, evidence: dict) -> None:
    findings.append({
        "id": finding_id,
        "severity": severity,
        "title": title,
        "evidence": evidence,
    })


def _security_posture(pe: pefile.PE, data: bytes, sections: list[dict]) -> dict:
    dll_characteristics = int(getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0))
    file_characteristics = int(getattr(pe.FILE_HEADER, "Characteristics", 0))
    architecture = MACHINE_NAMES.get(int(pe.FILE_HEADER.Machine), hex(int(pe.FILE_HEADER.Machine)))
    is_64bit = int(getattr(pe.OPTIONAL_HEADER, "Magic", 0)) == 0x20B
    mitigations = {
        name: {"enabled": bool(dll_characteristics & bit), "flag": hex(bit)}
        for name, bit in DLL_CHARACTERISTICS.items()
    }
    mitigations["high_entropy_va"]["applicable"] = is_64bit
    mitigations["dep"].update({
        "applicable": not is_64bit,
        "effective": is_64bit or mitigations["dep"]["enabled"],
        "note": "DEP is mandatory for native 64-bit images." if is_64bit else None,
    })
    mitigations["no_seh"]["applicable"] = architecture == "x86"

    reloc_directory = _directory(pe, "IMAGE_DIRECTORY_ENTRY_BASERELOC")
    reloc_size = int(getattr(reloc_directory, "Size", 0)) if reloc_directory else 0
    reloc_stripped = bool(file_characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    relocations = {
        "directory_present": reloc_size > 0,
        "directory_size": reloc_size,
        "stripped": reloc_stripped,
        "aslr_effective": mitigations["aslr"]["enabled"] and reloc_size > 0 and not reloc_stripped,
    }

    section_review = []
    writable_executable = []
    for section in sections:
        flags = int(section["characteristics"], 16)
        permissions = {
            "read": bool(flags & IMAGE_SCN_MEM_READ),
            "write": bool(flags & IMAGE_SCN_MEM_WRITE),
            "execute": bool(flags & IMAGE_SCN_MEM_EXECUTE),
            "code": bool(flags & IMAGE_SCN_CNT_CODE),
        }
        section["permissions"] = permissions
        if permissions["write"] and permissions["execute"]:
            writable_executable.append(section["name"])
        if section["raw_size"] == 0 and section["virtual_size"] > 0:
            section_review.append({"section": section["name"], "reason": "virtual_only"})
        if section["raw_size"] > section["virtual_size"] + 4096:
            section_review.append({"section": section["name"], "reason": "raw_size_exceeds_virtual_size"})

    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    entry_section = _section_for_rva(pe, entry_rva)
    entry_flags = int(entry_section.Characteristics) if entry_section is not None else 0
    entry_point = {
        "rva": entry_rva,
        "rva_hex": hex(entry_rva),
        "section": _section_name(entry_section) if entry_section is not None else None,
        "section_executable": bool(entry_flags & IMAGE_SCN_MEM_EXECUTE) if entry_section is not None else None,
    }

    signature = _authenticode(pe, data)
    debug = _debug_entries(pe, data)
    tls = _tls_callbacks(pe)
    load_config = _load_config(pe)
    overlay_offset = pe.get_overlay_data_start_offset()
    overlay_valid = overlay_offset is not None and 0 <= int(overlay_offset) <= len(data)
    overlay_size = len(data) - int(overlay_offset) if overlay_valid else 0
    overlay = {
        "present": overlay_size > 0,
        "file_offset": int(overlay_offset) if overlay_valid else None,
        "size": max(0, overlay_size),
        "contains_certificate_table": bool(
            overlay_valid
            and signature["present"]
            and int(signature["file_offset"]) >= int(overlay_offset)
        ),
    }

    findings = []
    if writable_executable:
        _append_finding(findings, "PE001", "high", "Writable and executable sections require review", {"sections": writable_executable})
    if entry_rva != 0 and entry_section is None:
        _append_finding(findings, "PE002", "high", "Entry point is not mapped to a section", {"rva": entry_rva})
    elif entry_rva != 0 and not entry_point["section_executable"]:
        _append_finding(findings, "PE003", "high", "Entry point is in a non-executable section", entry_point)
    if signature["present"] and not signature["bounds_valid"]:
        _append_finding(findings, "PE004", "high", "Certificate table extends beyond the file", signature)
    if not mitigations["aslr"]["enabled"]:
        _append_finding(findings, "PE101", "medium", "ASLR flag is disabled", {"dll_characteristics": hex(dll_characteristics)})
    elif not relocations["aslr_effective"]:
        _append_finding(findings, "PE102", "medium", "ASLR is requested without usable relocations", relocations)
    if not mitigations["dep"]["effective"]:
        _append_finding(findings, "PE103", "medium", "DEP/NX compatibility flag is disabled", {"dll_characteristics": hex(dll_characteristics)})
    if not mitigations["cfg"]["enabled"]:
        _append_finding(findings, "PE201", "low", "Control Flow Guard flag is disabled", {"dll_characteristics": hex(dll_characteristics)})
    if tls["callbacks"]:
        _append_finding(findings, "PE202", "info", "TLS callbacks execute before the entry point", {"callback_count": len(tls["callbacks"])})
    if is_64bit and not mitigations["high_entropy_va"]["enabled"]:
        _append_finding(findings, "PE203", "low", "High-entropy 64-bit ASLR flag is disabled", {"dll_characteristics": hex(dll_characteristics)})

    severity_counts = {level: 0 for level in ("high", "medium", "low", "info")}
    for finding in findings:
        severity_counts[finding["severity"]] += 1

    try:
        imphash = pe.get_imphash() or None
    except Exception:
        imphash = None

    return {
        "architecture": architecture,
        "is_64bit": is_64bit,
        "is_dll": bool(file_characteristics & IMAGE_FILE_DLL),
        "dll_characteristics": hex(dll_characteristics),
        "mitigations": mitigations,
        "relocations": relocations,
        "load_config": load_config,
        "entry_point": entry_point,
        "section_review": {
            "writable_executable": writable_executable,
            "size_anomalies": section_review,
        },
        "authenticode": signature,
        "debug": debug,
        "tls": tls,
        "overlay": overlay,
        "imphash": imphash,
        "findings": findings,
        "summary": severity_counts,
    }


def analyze_pe(path: Path, data: bytes | None = None) -> dict:
    out = {"is_pe": False}
    try:
        if data is None:
            _, data, _ = read_file_bytes(path)
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        out["error"] = f"PEFormatError: {exc}"
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    out["is_pe"] = True
    out["machine"] = hex(pe.FILE_HEADER.Machine)
    out["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    out["timestamp_utc"] = _timestamp(int(pe.FILE_HEADER.TimeDateStamp))
    out["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    out["entry_point_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    sections = []
    for section in pe.sections:
        raw = section.get_data()
        sections.append({
            "name": _section_name(section),
            "virtual_address": hex(section.VirtualAddress),
            "raw_offset": hex(section.PointerToRawData),
            "raw_size": int(section.SizeOfRawData),
            "virtual_size": int(section.Misc_VirtualSize),
            "entropy": round(entropy(raw), 3),
            "characteristics": hex(section.Characteristics),
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
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name": symbol.name.decode(errors="replace") if symbol.name else None,
                "ordinal": symbol.ordinal,
                "address": hex(symbol.address),
            })
    out["exports"] = exports
    try:
        out["security"] = _security_posture(pe, data, sections)
    except Exception as exc:
        out["security"] = {
            "error": f"{type(exc).__name__}: {exc}",
            "findings": [],
            "summary": {"high": 0, "medium": 0, "low": 0, "info": 0},
        }
    return out
