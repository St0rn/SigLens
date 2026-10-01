from __future__ import annotations
from pathlib import Path
from .utils import hashes, entropy
from .pe_analyzer import analyze_pe
from .fileio import read_file_bytes, normalize_path

def changed_ranges(a: bytes, b: bytes, max_ranges: int = 200) -> list[dict]:
    n = max(len(a), len(b))
    ranges = []
    start = None
    for i in range(n):
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None
        changed = ba != bb
        if changed and start is None:
            start = i
        elif not changed and start is not None:
            ranges.append({"start": start, "end": i, "length": i - start})
            start = None
            if len(ranges) >= max_ranges:
                break
    if start is not None and len(ranges) < max_ranges:
        ranges.append({"start": start, "end": n, "length": n - start})
    return ranges

def compare_files(old: Path, new: Path) -> dict:
    old, a, _ = read_file_bytes(old)
    new, b, _ = read_file_bytes(new)
    return {
        "old": {"path": str(old), "hashes": hashes(old, a), "entropy": round(entropy(a), 3), "pe": analyze_pe(old, a)},
        "new": {"path": str(new), "hashes": hashes(new, b), "entropy": round(entropy(b), 3), "pe": analyze_pe(new, b)},
        "changed_ranges": changed_ranges(a, b),
        "size_delta": len(b) - len(a),
    }
