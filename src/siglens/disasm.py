from __future__ import annotations
from pathlib import Path
from .fileio import read_file_bytes


def disassemble_window(path: Path, offset: int, size: int = 128, mode64: bool = True,
                       data: bytes | None = None) -> list[dict]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    except Exception:
        return []

    if data is None:
        _, data, _ = read_file_bytes(path)
    start = max(0, offset - size // 2)
    blob = data[start:start + size]
    md = Cs(CS_ARCH_X86, CS_MODE_64 if mode64 else CS_MODE_32)
    out = []
    for insn in md.disasm(blob, start):
        out.append({
            "offset": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
        })
    return out
