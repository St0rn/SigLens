from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from .addressing import file_offset_to_address


LOCATION_CLASSES = {
    "EXACT_MATCH",
    "NATIVE_ENGINE_OFFSET",
    "INFERRED_BOUNDARY",
    "CANDIDATE_REGION",
    "CONTEXT_DEPENDENT",
}


def verify_report_artifact(report: dict, data: bytes) -> None:
    expected = (
        report.get("file", {})
        .get("hashes", {})
        .get("sha256")
    )
    if not expected:
        raise ValueError("Report does not contain the analyzed artifact SHA-256")
    actual = hashlib.sha256(data).hexdigest()
    if str(expected).lower() != actual:
        raise ValueError(
            "Report/artifact SHA-256 mismatch; offsets cannot be applied safely"
        )


def _location(
    path: Path,
    data: bytes,
    offset: int,
    *,
    classification: str,
    provenance: dict,
    confidence: float | None,
    range_start: int | None = None,
    range_end: int | None = None,
    note: str | None = None,
) -> dict | None:
    if classification not in LOCATION_CLASSES:
        raise ValueError(f"Unsupported location classification: {classification}")
    if offset < 0 or offset >= len(data):
        return None

    mapping = file_offset_to_address(path, offset, data=data)
    rva = mapping.get("rva")
    va = mapping.get("va")
    image_base = mapping.get("image_base")
    if va is not None:
        navigation = (
            f"Ghidra Go To: 0x{int(va):X}. If the program is rebased, use "
            f"image base + RVA 0x{int(rva):X}."
        )
    else:
        navigation = (
            f"No PE memory address is available. Inspect file offset "
            f"0x{offset:X} in Ghidra's file-bytes/hex view."
        )

    return {
        "classification": classification,
        "confidence": confidence,
        "file_offset": offset,
        "file_offset_hex": f"0x{offset:X}",
        "range_start": range_start,
        "range_start_hex": f"0x{range_start:X}" if range_start is not None else None,
        "range_end": range_end,
        "range_end_hex": f"0x{range_end:X}" if range_end is not None else None,
        "section": mapping.get("section"),
        "rva": rva,
        "rva_hex": f"0x{int(rva):X}" if rva is not None else None,
        "va": va,
        "va_hex": f"0x{int(va):X}" if va is not None else None,
        "image_base": image_base,
        "image_base_hex": f"0x{int(image_base):X}" if image_base is not None else None,
        "ghidra_go_to": f"0x{int(va):X}" if va is not None else None,
        "navigation": navigation,
        "provenance": provenance,
        "note": note,
    }


def build_ghidra_locations(path: Path, data: bytes, report: dict) -> list[dict]:
    locations: list[dict] = []

    for match in report.get("yara", {}).get("matches", []):
        for string_match in match.get("strings", []):
            offset = string_match.get("offset")
            if not isinstance(offset, int):
                continue
            location = _location(
                path,
                data,
                offset,
                classification="EXACT_MATCH",
                confidence=1.0,
                provenance={
                    "type": "yara",
                    "rule": match.get("rule"),
                    "identifier": string_match.get("identifier"),
                    "matched_length": string_match.get("matched_length"),
                },
                range_start=offset,
                range_end=(
                    offset + int(string_match.get("matched_length", 0))
                    if string_match.get("matched_length") is not None else None
                ),
                note="Exact offset emitted by the YARA engine.",
            )
            if location:
                locations.append(location)

    for engine in report.get("multiav", {}).get("results", []):
        offset = engine.get("offset")
        if not isinstance(offset, int) or engine.get("offset_source") != "native_engine_output":
            continue
        location = _location(
            path,
            data,
            offset,
            classification="NATIVE_ENGINE_OFFSET",
            confidence=1.0,
            provenance={
                "type": "av_engine",
                "engine": engine.get("name"),
                "signature": engine.get("signature"),
            },
            note="Offset reported directly by the configured engine adapter.",
        )
        if location:
            locations.append(location)

    window_result = report.get("window_scan", {})
    for candidate in window_result.get("candidates", []):
        source_class = str(candidate.get("classification", ""))
        if source_class == "CONTEXT_DEPENDENT":
            classification = "CONTEXT_DEPENDENT"
        elif candidate.get("boundary_high") is not None:
            classification = "INFERRED_BOUNDARY"
        else:
            classification = "CANDIDATE_REGION"

        start = candidate.get("boundary_low", candidate.get("start"))
        end = candidate.get("boundary_high", candidate.get("end"))
        offset = candidate.get("inferred_offset")
        if not isinstance(offset, int):
            if isinstance(start, int):
                offset = start
            elif isinstance(end, int) and end > 0:
                offset = end - 1
        if not isinstance(offset, int):
            continue

        stability = candidate.get("stability", {})
        confidence = stability.get("confidence")
        location = _location(
            path,
            data,
            offset,
            classification=classification,
            confidence=float(confidence) if confidence is not None else None,
            provenance={
                "type": "prefix_narrowing",
                "source_classification": source_class or None,
                "scan_count": window_result.get("scan_count"),
                "non_monotonic_evidence": candidate.get("non_monotonic_evidence", []),
            },
            range_start=start if isinstance(start, int) else None,
            range_end=end if isinstance(end, int) else None,
            note=(
                "Experimental prefix observation; this is not a native engine offset."
            ),
        )
        if location:
            locations.append(location)

    for region in report.get("component_scan", {}).get("regions", []):
        if int(region.get("summary", {}).get("detected", 0) or 0) <= 0:
            continue
        offset = region.get("offset")
        if not isinstance(offset, int):
            continue
        location = _location(
            path,
            data,
            offset,
            classification="CANDIDATE_REGION",
            confidence=None,
            provenance={
                "type": "pe_component_scan",
                "region": region.get("name"),
                "kind": region.get("kind"),
            },
            range_start=offset,
            range_end=region.get("end") if isinstance(region.get("end"), int) else None,
            note="Detected PE region; attribution inside the region is not exact.",
        )
        if location:
            locations.append(location)

    seen = set()
    unique = []
    for location in locations:
        key = (
            location["classification"],
            location["file_offset"],
            repr(location["provenance"]),
        )
        if key not in seen:
            seen.add(key)
            unique.append(location)
    return unique


def save_ghidra_csv(locations: list[dict], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "classification",
        "confidence",
        "file_offset_hex",
        "range_start_hex",
        "range_end_hex",
        "section",
        "rva_hex",
        "va_hex",
        "image_base_hex",
        "ghidra_go_to",
        "navigation",
        "note",
        "provenance",
    ]
    with output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for location in locations:
            writer.writerow({key: location.get(key) for key in columns})
    return output


def save_ghidra_script(
    locations: list[dict],
    expected_sha256: str,
    output: Path,
) -> Path:
    """Write a Ghidra Jython script that adds verified RVA bookmarks."""
    normalized_hash = str(expected_sha256).lower()
    if len(normalized_hash) != 64 or any(char not in "0123456789abcdef" for char in normalized_hash):
        raise ValueError("Expected artifact SHA-256 must contain 64 hexadecimal characters")

    mapped = []
    for location in locations:
        rva = location.get("rva")
        if type(rva) is not int or rva < 0:
            continue
        mapped.append({
            "rva": rva,
            "classification": str(location.get("classification") or "CANDIDATE_REGION"),
            "file_offset_hex": str(location.get("file_offset_hex") or ""),
            "confidence": location.get("confidence"),
            "note": location.get("note"),
            "provenance": location.get("provenance", {}),
        })

    encoded_locations = repr(json.dumps(mapped, ensure_ascii=True, separators=(",", ":")))
    expected = repr(normalized_hash)
    script = f'''# SigLens Ghidra bookmark importer
#@category SigLens
# Generated from a hash-verified SigLens report. Review bookmarks before editing source.

import json

EXPECTED_SHA256 = {expected}
LOCATIONS = json.loads({encoded_locations})

actual_sha256 = currentProgram.getExecutableSHA256()
if not actual_sha256:
    raise RuntimeError("SigLens refused import: Ghidra did not expose the executable SHA-256")
if str(actual_sha256).lower() != EXPECTED_SHA256:
    raise RuntimeError("SigLens refused import: current program SHA-256 does not match the report")

image_base = currentProgram.getImageBase()
memory = currentProgram.getMemory()
bookmarks = currentProgram.getBookmarkManager()
created = 0
skipped = 0

for item in LOCATIONS:
    address = image_base.add(int(item["rva"]))
    if not memory.contains(address):
        skipped += 1
        continue
    details = {{
        "file_offset": item.get("file_offset_hex"),
        "confidence": item.get("confidence"),
        "note": item.get("note"),
        "provenance": item.get("provenance"),
    }}
    function = getFunctionContaining(address)
    if function:
        details["ghidra_function"] = str(function.getName(True))
    category = "SigLens/" + item["classification"]
    bookmarks.setBookmark(address, "Note", category, json.dumps(details, sort_keys=True))
    created += 1

print("SigLens: created {{0}} bookmark(s), skipped {{1}} unmapped location(s)".format(created, skipped))
'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(script, encoding="utf-8", newline="\n")
    return output
