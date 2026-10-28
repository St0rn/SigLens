from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Iterable

from . import __author__, __version__
from .correlation import correlate_offset
from .report import report_metadata


SOURCE_MAP_SCHEMA = "siglens-source-map/v1"
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cs"}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}


def load_source_map(path: Path, data: bytes) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("Source map JSON root must be an object")
    if payload.get("schema") != SOURCE_MAP_SCHEMA:
        raise ValueError(f"Source map schema must be {SOURCE_MAP_SCHEMA}")
    expected = payload.get("artifact_sha256")
    actual = hashlib.sha256(data).hexdigest()
    if not expected or str(expected).lower() != actual:
        raise ValueError("Source map/artifact SHA-256 mismatch")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("Source map entries must be an array")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"Source map entry {index} must be an object")
        has_rva = type(entry.get("rva_start")) is int and type(entry.get("rva_end")) is int
        has_file = (
            type(entry.get("file_offset_start")) is int
            and type(entry.get("file_offset_end")) is int
        )
        if not has_rva and not has_file:
            raise ValueError(
                f"Source map entry {index} requires an RVA or file-offset range"
            )
        if has_rva and entry["rva_end"] <= entry["rva_start"]:
            raise ValueError(f"Source map entry {index} has an invalid RVA range")
        if has_file and entry["file_offset_end"] <= entry["file_offset_start"]:
            raise ValueError(f"Source map entry {index} has an invalid file-offset range")
    return payload


def parse_msvc_map(path: Path) -> list[dict]:
    """Parse public-symbol rows from a Microsoft linker MAP file."""
    pattern = re.compile(
        r"^\s*(?P<section>[0-9A-Fa-f]{4}):(?P<offset>[0-9A-Fa-f]{8,16})"
        r"\s+(?P<symbol>\S+)\s+(?P<va>[0-9A-Fa-f]{8,16})"
        r"(?:\s+[fFiI])?(?:\s+(?P<object>\S+))?\s*$"
    )
    entries = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        entries.append({
            "section": int(match.group("section"), 16),
            "section_offset": int(match.group("offset"), 16),
            "symbol": match.group("symbol"),
            "va": int(match.group("va"), 16),
            "object_file": match.group("object"),
        })
    entries.sort(key=lambda item: item["va"])
    return entries


def _range_match(location: dict, entry: dict) -> tuple[bool, int]:
    rva = location.get("rva")
    if type(rva) is int and type(entry.get("rva_start")) is int:
        start, end = entry["rva_start"], entry["rva_end"]
        return start <= rva < end, end - start
    offset = location.get("file_offset")
    if type(offset) is int and type(entry.get("file_offset_start")) is int:
        start, end = entry["file_offset_start"], entry["file_offset_end"]
        return start <= offset < end, end - start
    return False, 0


def resolve_source_map(location: dict, source_map: dict | None) -> dict | None:
    if not source_map:
        return None
    matches = []
    for entry in source_map.get("entries", []):
        matched, size = _range_match(location, entry)
        if matched:
            matches.append((size, entry))
    if not matches:
        return None
    _, entry = min(matches, key=lambda item: item[0])
    return {
        "method": "verified_source_map",
        "confidence": "high",
        "language": entry.get("language") or source_map.get("language"),
        "symbol": entry.get("symbol"),
        "source_file": entry.get("source_file"),
        "source_line": entry.get("source_start_line"),
        "source_end_line": entry.get("source_end_line"),
        "range": {
            key: entry.get(key)
            for key in ("rva_start", "rva_end", "file_offset_start", "file_offset_end")
            if entry.get(key) is not None
        },
    }


def resolve_linker_map(va: int | None, entries: list[dict]) -> dict | None:
    if type(va) is not int or not entries:
        return None
    previous = None
    following_va = None
    for entry in entries:
        if entry["va"] <= va:
            previous = entry
        else:
            following_va = entry["va"]
            break
    if previous is None:
        return None
    if va - previous["va"] > 0x100000:
        return None
    if following_va is not None and va >= following_va:
        return None
    return {
        "method": "msvc_linker_map",
        "confidence": "medium",
        "language": "cpp",
        "symbol": previous.get("symbol"),
        "source_file": None,
        "source_line": None,
        "source_end_line": None,
        "object_file": previous.get("object_file"),
        "symbol_va": previous.get("va"),
        "displacement": va - previous["va"],
    }


def _under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_source_file(raw: str | None, source_root: Path | None) -> Path | None:
    if not raw or source_root is None:
        return None
    root = source_root.resolve()
    original = Path(raw)
    candidates = []
    if original.is_absolute():
        candidates.append(original)
    else:
        candidates.append(root / original)

    normalized_parts = [part for part in raw.replace("\\", "/").split("/") if part and ":" not in part]
    for index in range(len(normalized_parts)):
        candidates.append(root.joinpath(*normalized_parts[index:]))

    for candidate in candidates:
        if candidate.is_file() and _under_root(candidate, root):
            return candidate.resolve()

    name = normalized_parts[-1] if normalized_parts else original.name
    if name:
        matches = []
        for candidate in root.rglob(name):
            if (
                candidate.is_file()
                and candidate.suffix.lower() in SOURCE_EXTENSIONS
                and _under_root(candidate, root)
            ):
                matches.append(candidate.resolve())
                if len(matches) > 10:
                    break
        if len(matches) == 1:
            return matches[0]
    return None


def _source_context(path: Path, line: int | None, end_line: int | None, context: int) -> list[dict]:
    if type(line) is not int or line < 1:
        return []
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    final = end_line if type(end_line) is int and end_line >= line else line
    final = min(final, line + 50)
    start_index = max(0, line - 1 - context)
    end_index = min(len(lines), final + context)
    return [
        {
            "line": index + 1,
            "text": lines[index],
            "highlight": line <= index + 1 <= final,
        }
        for index in range(start_index, end_index)
    ]


def _symbol_identifier(symbol: str | None) -> str | None:
    if not symbol:
        return None
    decorated = re.match(r"^\?([^@?$]+)@", symbol)
    if decorated:
        return decorated.group(1)
    value = symbol.split("(", 1)[0].strip()
    value = re.split(r"::|\.", value)[-1]
    match = re.search(r"[A-Za-z_][A-Za-z0-9_]*$", value)
    return match.group(0) if match and len(match.group(0)) >= 3 else None


def search_source_symbol(source_root: Path | None, symbol: str | None, limit: int = 10) -> list[dict]:
    identifier = _symbol_identifier(symbol)
    if source_root is None or identifier is None:
        return []
    root = source_root.resolve()
    pattern = re.compile(rf"\b{re.escape(identifier)}\s*\(")
    matches = []
    scanned = 0
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.suffix.lower() not in SOURCE_EXTENSIONS
            or not _under_root(path, root)
        ):
            continue
        scanned += 1
        if scanned > 5000:
            break
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            continue
        for index, text in enumerate(lines):
            if pattern.search(text):
                matches.append({
                    "method": "source_symbol_text_match",
                    "confidence": "low",
                    "language": "csharp" if path.suffix.lower() == ".cs" else "cpp",
                    "symbol": symbol,
                    "source_file": str(path.resolve()),
                    "source_line": index + 1,
                    "source_end_line": index + 1,
                })
                if len(matches) >= limit:
                    return matches
    return matches


def _add_context(candidate: dict, source_root: Path | None, context_lines: int) -> dict:
    result = dict(candidate)
    path = _resolve_source_file(result.get("source_file"), source_root)
    if path is not None:
        result["resolved_source_file"] = str(path)
        result["context"] = _source_context(
            path,
            result.get("source_line"),
            result.get("source_end_line"),
            context_lines,
        )
    else:
        result["resolved_source_file"] = None
        result["context"] = []
    return result


def _deduplicate(candidates: Iterable[dict]) -> list[dict]:
    unique = []
    seen = set()
    for candidate in candidates:
        key = (
            candidate.get("method"),
            candidate.get("symbol"),
            candidate.get("source_file"),
            candidate.get("source_line"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return sorted(unique, key=lambda item: CONFIDENCE_ORDER.get(item.get("confidence"), 9))


def attribute_source_locations(
    artifact: Path,
    data: bytes,
    report: dict,
    *,
    symbol_path: Path | None = None,
    source_map: dict | None = None,
    linker_map: list[dict] | None = None,
    source_root: Path | None = None,
    context_lines: int = 3,
) -> dict:
    attributions = []
    for location in report.get("ghidra_locations", []):
        if not isinstance(location, dict) or type(location.get("file_offset")) is not int:
            continue
        correlation = correlate_offset(
            artifact,
            location["file_offset"],
            symbol_path=symbol_path,
            data=data,
        )
        candidates = []
        mapped = resolve_source_map(location, source_map)
        if mapped:
            candidates.append(mapped)

        symbols = correlation.get("symbols") or {}
        if symbols.get("resolved"):
            candidates.append({
                "method": "dbghelp_pdb",
                "confidence": "high" if symbols.get("source_file") else "medium",
                "language": "cpp",
                "symbol": symbols.get("symbol"),
                "source_file": symbols.get("source_file"),
                "source_line": symbols.get("source_line"),
                "source_end_line": symbols.get("source_line"),
                "displacement": symbols.get("displacement"),
            })

        linker = resolve_linker_map(location.get("va"), linker_map or [])
        if linker:
            candidates.append(linker)

        symbols_to_search = [
            candidate.get("symbol") for candidate in candidates if candidate.get("symbol")
        ]
        runtime = correlation.get("runtime_function") or {}
        if runtime.get("label"):
            symbols_to_search.append(runtime["label"])
        for symbol in dict.fromkeys(symbols_to_search):
            candidates.extend(search_source_symbol(source_root, symbol))

        candidates = _deduplicate(
            _add_context(candidate, source_root, context_lines)
            for candidate in candidates
        )
        primary = candidates[0] if candidates else None
        attributions.append({
            "classification": location.get("classification"),
            "location_confidence": location.get("confidence"),
            "file_offset": location.get("file_offset"),
            "file_offset_hex": location.get("file_offset_hex"),
            "rva": location.get("rva"),
            "rva_hex": location.get("rva_hex"),
            "va": location.get("va"),
            "va_hex": location.get("va_hex"),
            "section": location.get("section"),
            "ghidra_go_to": location.get("ghidra_go_to"),
            "provenance": location.get("provenance", {}),
            "runtime_function": correlation.get("runtime_function"),
            "symbols": symbols,
            "disassembly": correlation.get("disassembly", [])[:32],
            "source_candidates": candidates,
            "primary_source": primary,
            "attribution_confidence": primary.get("confidence") if primary else "none",
        })

    return {
        **report_metadata("source_attribution"),
        "tool": {"name": "SigLens", "version": __version__, "author": __author__},
        "file": report.get("file", {}),
        "ghidra_locations": report.get("ghidra_locations", []),
        "source_map": {
            "provided": source_map is not None,
            "schema": source_map.get("schema") if source_map else None,
            "language": source_map.get("language") if source_map else None,
        },
        "attributions": attributions,
        "summary": {
            "location_count": len(attributions),
            "resolved_count": sum(item["primary_source"] is not None for item in attributions),
            "high_confidence_count": sum(
                item["attribution_confidence"] == "high" for item in attributions
            ),
        },
        "limitations": [
            "Exact source lines require matching debug symbols or a SHA-256-bound source map.",
            "Textual symbol matches are candidates and can be ambiguous for overloads or generated code.",
            "Inferred detection boundaries do not prove that one source function independently causes a verdict.",
        ],
    }
