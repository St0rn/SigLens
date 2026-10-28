from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from . import __version__
from .report import save_json_document


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _rule_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._/-]+", "_", value).strip("_")
    return cleaned[:200] or "SigLens/Finding"


def _location_rule(location: dict) -> tuple[str, str]:
    provenance = location.get("provenance", {})
    source_type = str(provenance.get("type") or "location")
    if source_type == "yara":
        name = str(provenance.get("rule") or "match")
        return _rule_id(f"YARA/{name}"), f"YARA rule {name}"
    if source_type == "av_engine":
        engine = str(provenance.get("engine") or "engine")
        return _rule_id(f"AV/{engine}"), f"Native offset from {engine}"
    classification = str(location.get("classification") or "CANDIDATE_REGION")
    return _rule_id(f"SigLens/{classification}"), classification.replace("_", " ").title()


def _artifact_uri(report: dict) -> str:
    value = str(report.get("file", {}).get("path") or "artifact.bin")
    return value.replace("\\", "/")


def _fingerprint(report: dict, *parts: object) -> str:
    sha256 = report.get("file", {}).get("hashes", {}).get("sha256") or ""
    material = json.dumps([sha256, *parts], sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_sarif(report: dict) -> dict:
    artifact_uri = _artifact_uri(report)
    artifact = {"location": {"uri": artifact_uri}}
    artifact_hash = report.get("file", {}).get("hashes", {}).get("sha256")
    if artifact_hash:
        artifact["hashes"] = {"sha-256": artifact_hash}
    rules: dict[str, dict] = {}
    results = []

    for location in report.get("ghidra_locations", []):
        if not isinstance(location, dict):
            continue
        rule_id, rule_name = _location_rule(location)
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_name,
            "shortDescription": {"text": rule_name},
            "properties": {"tags": ["security", "siglens", "binary-analysis"]},
        })
        classification = str(location.get("classification") or "CANDIDATE_REGION")
        offset = location.get("file_offset")
        region = {"byteOffset": offset} if type(offset) is int else {}
        start = location.get("range_start")
        end = location.get("range_end")
        if type(start) is int:
            region["byteOffset"] = start
        if type(start) is int and type(end) is int and end > start:
            region["byteLength"] = end - start
        physical = {"artifactLocation": {"uri": artifact_uri}}
        if region:
            physical["region"] = region
        results.append({
            "ruleId": rule_id,
            "level": "warning" if classification in {"EXACT_MATCH", "NATIVE_ENGINE_OFFSET"} else "note",
            "message": {"text": location.get("note") or f"SigLens {classification} location"},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {
                "siglens/v1": _fingerprint(
                    report, classification, offset, location.get("provenance", {})
                )
            },
            "properties": {
                "classification": classification,
                "confidence": location.get("confidence"),
                "fileOffset": offset,
                "rva": location.get("rva"),
                "va": location.get("va"),
                "section": location.get("section"),
                "provenance": location.get("provenance", {}),
            },
        })

    for engine in report.get("multiav", {}).get("results", []):
        if not isinstance(engine, dict) or str(engine.get("status")).lower() != "detected":
            continue
        name = str(engine.get("name") or "Unknown engine")
        rule_id = _rule_id(f"AV/{name}")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f"Detection by {name}",
            "shortDescription": {"text": f"Artifact detection reported by {name}"},
            "properties": {"tags": ["security", "siglens", "antivirus"]},
        })
        results.append({
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": f"{name}: {engine.get('signature') or 'detected'}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}],
            "partialFingerprints": {
                "siglens/v1": _fingerprint(report, "engine", name, engine.get("signature"))
            },
            "properties": {
                "engine": name,
                "signature": engine.get("signature"),
                "status": "detected",
                "nativeOffset": engine.get("offset") if engine.get("offset_source") == "native_engine_output" else None,
            },
        })

    amsi = report.get("amsi", {})
    if isinstance(amsi, dict) and str(amsi.get("status")).lower() == "detected":
        rule_id = "AMSI/Detected"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": "AMSI full-buffer detection",
            "shortDescription": {"text": "Windows AMSI detected the complete artifact buffer"},
            "properties": {"tags": ["security", "siglens", "amsi"]},
        })
        results.append({
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": str(amsi.get("result_name") or "AMSI detected the artifact")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}],
            "partialFingerprints": {"siglens/v1": _fingerprint(report, "amsi", "detected")},
            "properties": {"scanScope": "complete_file_buffer"},
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "SigLens",
                "version": str(report.get("tool", {}).get("version") or __version__),
                "informationUri": "https://github.com/St0rn/SigLens",
                "rules": list(rules.values()),
            }},
            "artifacts": [artifact],
            "results": results,
            "properties": {
                "siglensSchema": report.get("schema"),
                "siglensSchemaVersion": report.get("schema_version"),
            },
        }],
    }


def save_sarif(report: dict, output: Path) -> Path:
    return save_json_document(build_sarif(report), output)
