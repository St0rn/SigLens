import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from siglens.report_diff import compare_reports


def _report(data: bytes, *, detected: bool) -> dict:
    functions = ["CreateFileW"]
    if detected:
        functions.append("VirtualAlloc")
    return {
        "schema": "siglens-report/v1",
        "schema_version": "1.0.0",
        "report_type": "artifact_analysis",
        "generated_at": "2026-10-28T12:00:00+00:00",
        "file": {
            "path": "sample.exe",
            "hashes": {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        },
        "multiav": {"results": [{
            "name": "Lab AV",
            "status": "detected" if detected else "clean",
            "signature": "Lab.Signature" if detected else None,
        }]},
        "amsi": {"status": "detected" if detected else "clean"},
        "yara": {"matches": [{"rule": "NewRule"}]} if detected else {"matches": []},
        "pe": {"imports": [{
            "dll": "KERNEL32.dll",
            "functions": functions,
        }]},
        "ghidra_locations": ([{
            "classification": "EXACT_MATCH",
            "file_offset": 0,
            "file_offset_hex": "0x0",
        }] if detected else []),
    }


def test_compares_detection_evidence_and_validates_schema():
    old = _report(b"old", detected=False)
    new = _report(b"new", detected=True)
    comparison = compare_reports(old, new)

    assert comparison["report_type"] == "comparison"
    assert comparison["summary"]["changed"] is True
    assert comparison["summary"]["newly_detected_engines"] == ["Lab AV"]
    assert comparison["amsi"] == {"old": "clean", "new": "detected", "changed": True}
    assert comparison["yara"]["added_rules"] == ["NewRule"]
    assert comparison["imports"]["added"] == ["KERNEL32.dll!VirtualAlloc"]
    assert comparison["location_changes"]["new_by_classification"] == {"EXACT_MATCH": 1}
    assert comparison["comparability"]["same_engine_set"] is True
    assert comparison["comparability"]["warnings"] == []

    schema_path = Path(__file__).parents[1] / "schemas" / "siglens-report-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(comparison)


def test_reports_no_changes_for_identical_evidence():
    report = _report(b"same", detected=False)
    comparison = compare_reports(report, report)
    assert comparison["summary"]["changed"] is False
    assert comparison["summary"]["change_count"] == 0


def test_warns_when_lab_inputs_are_not_comparable():
    old = _report(b"old", detected=False)
    new = _report(b"new", detected=False)
    new["multiav"]["results"].append({"name": "Second AV", "status": "clean"})
    new["tool"] = {"version": "different"}
    comparison = compare_reports(old, new)
    assert comparison["comparability"]["same_engine_set"] is False
    assert comparison["comparability"]["same_tool_version"] is False
    assert len(comparison["comparability"]["warnings"]) == 2
