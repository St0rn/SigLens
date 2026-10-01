from __future__ import annotations
import re

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

def extract_strings(data: bytes, limit: int = 5000) -> dict:
    ascii_s = [m.group().decode("ascii", errors="replace") for m in ASCII_RE.finditer(data)]
    utf16_s = [m.group().decode("utf-16le", errors="replace") for m in UTF16_RE.finditer(data)]
    return {
        "ascii": ascii_s[:limit],
        "utf16le": utf16_s[:limit],
        "truncated": len(ascii_s) > limit or len(utf16_s) > limit,
    }
