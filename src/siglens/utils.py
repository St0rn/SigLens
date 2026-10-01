from __future__ import annotations
from pathlib import Path
import hashlib, math, shutil, subprocess
from collections import Counter
from .fileio import read_file_bytes


def hashes(path: Path, data: bytes | None = None) -> dict:
    if data is None:
        _, data, _ = read_file_bytes(path)
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def resolve_tool(name: str, root: Path | None = None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if root:
        candidate = root / "tools" / name
        if candidate.exists():
            return str(candidate)
    return None


def run_command(args: list[str], timeout: int = 120) -> dict:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "args": args,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "args": args}
