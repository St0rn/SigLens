from __future__ import annotations
from pathlib import Path
from .fileio import read_file_bytes


def _iter_rule_files(path: Path):
    if path.is_file():
        yield path
    elif path.is_dir():
        for p in sorted(path.rglob("*")):
            if p.suffix.lower() in {".yar", ".yara"}:
                yield p


def scan(path: Path, rules_path: Path, data: bytes | None = None) -> dict:
    try:
        import yara
    except Exception as e:
        return {"available": False, "error": str(e), "matches": []}

    rule_files = list(_iter_rule_files(rules_path))
    if not rule_files:
        return {"available": True, "error": "No YARA rules found", "matches": []}

    namespaces = {f"r{i}": str(p) for i, p in enumerate(rule_files)}
    try:
        rules = yara.compile(filepaths=namespaces)
        if data is None:
            _, data, _ = read_file_bytes(path)
        matches = rules.match(data=data)
    except Exception as e:
        return {"available": True, "error": str(e), "matches": []}

    out = []
    for m in matches:
        strings = []
        for sm in getattr(m, "strings", []):
            identifier = getattr(sm, "identifier", None)
            instances = getattr(sm, "instances", None)
            if instances is not None:
                for inst in instances:
                    strings.append({
                        "identifier": identifier,
                        "offset": int(inst.offset),
                        "matched_length": int(inst.matched_length),
                    })
            else:
                try:
                    off, ident, blob = sm
                    strings.append({
                        "identifier": ident,
                        "offset": int(off),
                        "matched_length": len(blob),
                    })
                except Exception:
                    pass
        out.append({
            "rule": m.rule,
            "namespace": getattr(m, "namespace", None),
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "strings": strings,
        })
    return {"available": True, "matches": out}
