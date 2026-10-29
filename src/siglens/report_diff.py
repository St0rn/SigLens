from __future__ import annotations

from collections import Counter

from . import __author__, __version__
from .report import report_metadata


def _artifact(report: dict) -> dict:
    file_info = report.get("file", {})
    hashes = file_info.get("hashes", {}) if isinstance(file_info, dict) else {}
    return {
        "path": file_info.get("path") if isinstance(file_info, dict) else None,
        "sha256": hashes.get("sha256") if isinstance(hashes, dict) else None,
        "size": hashes.get("size") if isinstance(hashes, dict) else None,
        "generated_at": report.get("generated_at"),
        "tool_version": report.get("tool", {}).get("version"),
    }


def _engine_map(report: dict) -> dict[str, dict]:
    results = report.get("multiav", {}).get("results", [])
    mapped = {}
    for item in results if isinstance(results, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "<unnamed>")
        mapped[name] = {
            "status": str(item.get("status") or "unknown").lower(),
            "signature": item.get("signature"),
            "offset": item.get("offset"),
            "offset_source": item.get("offset_source"),
        }
    return mapped


def _yara_rules(report: dict) -> set[str]:
    matches = report.get("yara", {}).get("matches", [])
    return {
        str(match.get("rule"))
        for match in matches if isinstance(match, dict) and match.get("rule")
    }


def _imports(report: dict) -> set[str]:
    imports = set()
    for library in report.get("pe", {}).get("imports", []):
        if not isinstance(library, dict):
            continue
        dll = str(library.get("dll") or "<unknown>")
        for function in library.get("functions", []):
            imports.add(f"{dll}!{function}")
    return imports


def _location_classes(report: dict) -> dict[str, int]:
    values = Counter()
    for location in report.get("ghidra_locations", []):
        if isinstance(location, dict):
            values[str(location.get("classification") or "UNKNOWN")] += 1
    return dict(sorted(values.items()))


def _pe_security(report: dict) -> dict:
    value = report.get("pe", {}).get("security", {})
    security = value if isinstance(value, dict) else {}
    mitigations = security.get("mitigations", {})
    return {
        "mitigations": {
            str(name): bool(item.get("enabled"))
            for name, item in mitigations.items()
            if isinstance(item, dict)
        },
        "aslr_effective": security.get("relocations", {}).get("aslr_effective"),
        "writable_executable": sorted(security.get("section_review", {}).get("writable_executable", [])),
        "authenticode_present": security.get("authenticode", {}).get("present"),
        "imphash": security.get("imphash"),
        "finding_ids": sorted(
            str(item.get("id"))
            for item in security.get("findings", [])
            if isinstance(item, dict) and item.get("id")
        ),
    }


def _status(report: dict, key: str) -> str | None:
    value = report.get(key, {})
    if not isinstance(value, dict):
        return None
    status = value.get("status")
    return str(status).lower() if status is not None else None


def compare_reports(old: dict, new: dict) -> dict:
    old_engines = _engine_map(old)
    new_engines = _engine_map(new)
    transitions = []
    newly_detected = []
    no_longer_detected = []
    signature_changes = []

    for name in sorted(set(old_engines) | set(new_engines), key=str.casefold):
        before = old_engines.get(name, {"status": "not_run", "signature": None})
        after = new_engines.get(name, {"status": "not_run", "signature": None})
        changed = before != after
        transition = {
            "engine": name,
            "old": before,
            "new": after,
            "changed": changed,
        }
        transitions.append(transition)
        if before.get("status") != "detected" and after.get("status") == "detected":
            newly_detected.append(name)
        if before.get("status") == "detected" and after.get("status") != "detected":
            no_longer_detected.append(name)
        if before.get("signature") != after.get("signature"):
            signature_changes.append(name)

    old_yara = _yara_rules(old)
    new_yara = _yara_rules(new)
    old_imports = _imports(old)
    new_imports = _imports(new)
    old_locations = _location_classes(old)
    new_locations = _location_classes(new)
    old_pe_security = _pe_security(old)
    new_pe_security = _pe_security(new)
    old_amsi = _status(old, "amsi")
    new_amsi = _status(new, "amsi")
    same_engine_set = set(old_engines) == set(new_engines)
    same_tool_version = old.get("tool", {}).get("version") == new.get("tool", {}).get("version")
    comparability_warnings = []
    if not same_engine_set:
        comparability_warnings.append(
            "Engine sets differ; missing or added adapters can produce apparent verdict transitions."
        )
    if not same_tool_version:
        comparability_warnings.append(
            "SigLens versions differ; review schema and analysis changes before attributing every difference to the artifact."
        )
    if (old_amsi is None) != (new_amsi is None):
        comparability_warnings.append(
            "AMSI was recorded in only one report; this transition is not directly comparable."
        )

    change_count = sum(item["changed"] for item in transitions)
    change_count += len(old_yara ^ new_yara)
    change_count += len(old_imports ^ new_imports)
    change_count += int(old_amsi != new_amsi)
    change_count += int(old_locations != new_locations)
    pe_security_changed = old_pe_security != new_pe_security
    change_count += int(pe_security_changed)

    return {
        **report_metadata("comparison"),
        "tool": {"name": "SigLens", "version": __version__, "author": __author__},
        "comparison_kind": "siglens_report_diff",
        "old": _artifact(old),
        "new": _artifact(new),
        "summary": {
            "changed": bool(change_count),
            "change_count": change_count,
            "engine_transition_count": sum(item["changed"] for item in transitions),
            "newly_detected_engines": newly_detected,
            "no_longer_detected_engines": no_longer_detected,
            "signature_change_engines": signature_changes,
        },
        "comparability": {
            "same_schema": (
                old.get("schema") == new.get("schema")
                and old.get("schema_version") == new.get("schema_version")
            ),
            "same_tool_version": same_tool_version,
            "same_engine_set": same_engine_set,
            "warnings": comparability_warnings,
        },
        "engine_transitions": transitions,
        "amsi": {"old": old_amsi, "new": new_amsi, "changed": old_amsi != new_amsi},
        "yara": {
            "added_rules": sorted(new_yara - old_yara),
            "removed_rules": sorted(old_yara - new_yara),
            "unchanged_rules": sorted(old_yara & new_yara),
        },
        "imports": {
            "added": sorted(new_imports - old_imports),
            "removed": sorted(old_imports - new_imports),
        },
        "location_changes": {
            "old_by_classification": old_locations,
            "new_by_classification": new_locations,
            "changed": old_locations != new_locations,
        },
        "pe_security": {
            "old": old_pe_security,
            "new": new_pe_security,
            "changed": pe_security_changed,
            "added_writable_executable_sections": sorted(
                set(new_pe_security["writable_executable"]) - set(old_pe_security["writable_executable"])
            ),
            "removed_writable_executable_sections": sorted(
                set(old_pe_security["writable_executable"]) - set(new_pe_security["writable_executable"])
            ),
            "added_findings": sorted(set(new_pe_security["finding_ids"]) - set(old_pe_security["finding_ids"])),
            "removed_findings": sorted(set(old_pe_security["finding_ids"]) - set(new_pe_security["finding_ids"])),
        },
        "limitations": [
            "Verdict transitions are comparable only when engine versions, policies, definitions, and host conditions are controlled.",
            "A changed detection state does not identify the source-level cause by itself.",
        ],
    }
