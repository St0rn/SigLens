from __future__ import annotations
from pathlib import Path
from .addressing import file_offset_to_address
from .functions import resolve_runtime_function
from .symbols import resolve_with_dbghelp
from .disasm import disassemble_window


def correlate_offset(path: Path, offset: int, symbol_path: Path | None = None,
                     disasm_bytes: int = 192, data: bytes | None = None) -> dict:
    address = file_offset_to_address(path, offset, data=data)
    result = {
        "offset": offset,
        "offset_hex": hex(offset),
        "address": address,
        "runtime_function": None,
        "symbols": None,
        "disassembly": [],
    }
    if not address.get("mapped"):
        return result

    rva = int(address["rva"])
    va = int(address["va"])
    runtime = resolve_runtime_function(path, rva, data=data)
    result["runtime_function"] = runtime
    result["symbols"] = resolve_with_dbghelp(path, va, symbol_path)

    # Prefer disassembly from the discovered function start, otherwise use the hit offset.
    start_raw = runtime.get("begin_file_offset") if runtime and runtime.get("resolved") else None
    disasm_offset = int(start_raw) if start_raw is not None else offset
    result["disassembly"] = disassemble_window(path, disasm_offset, disasm_bytes, True, data=data)[:80]
    return result
