import hashlib

import pytest

from siglens.report import save_json
from siglens.report_validation import (
    ReportValidationError,
    load_report,
    validate_report,
)


def _valid_report(data: bytes) -> dict:
    return {
        "schema": "siglens-report/v1",
        "schema_version": "1.0.0",
        "report_type": "artifact_analysis",
        "generated_at": "2026-10-28T12:00:00+00:00",
        "file": {
            "hashes": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            },
        },
        "ghidra_locations": [{
            "classification": "EXACT_MATCH",
            "confidence": 1.0,
            "file_offset": 2,
            "file_offset_hex": "0x2",
            "range_start": 2,
            "range_end": 4,
            "rva": 0x1002,
            "rva_hex": "0x1002",
            "va": 0x401002,
            "va_hex": "0x401002",
            "image_base": 0x400000,
            "image_base_hex": "0x400000",
        }],
    }


def test_round_trip_and_artifact_validation(tmp_path):
    data = b"01234567"
    output = save_json(_valid_report(data), tmp_path / "report.json")
    loaded = load_report(output)
    summary = validate_report(loaded, artifact_data=data)
    assert summary["valid"] is True
    assert summary["artifact_verified"] is True
    assert summary["ghidra_location_count"] == 1
    assert not list(tmp_path.glob(".report.json.*.tmp"))


def test_rejects_duplicate_json_keys(tmp_path):
    output = tmp_path / "duplicate.json"
    output.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        load_report(output)


def test_reports_semantic_address_and_artifact_errors():
    data = b"01234567"
    report = _valid_report(data)
    report["ghidra_locations"][0]["file_offset_hex"] = "0x3"
    report["ghidra_locations"][0]["va"] += 1
    report["ghidra_locations"][0]["range_start"] = 3
    with pytest.raises(ReportValidationError) as caught:
        validate_report(report, artifact_data=b"different")
    messages = [str(issue) for issue in caught.value.issues]
    assert any("file_offset_hex" in message for message in messages)
    assert any("image base + RVA" in message for message in messages)
    assert any("reported range" in message for message in messages)
    assert any("supplied artifact" in message for message in messages)


def test_rejects_invalid_schema():
    with pytest.raises(ReportValidationError) as caught:
        validate_report({"schema": "unknown"})
    assert any(issue.path == "$.schema" for issue in caught.value.issues)


def test_artifact_verification_requires_reported_size():
    data = b"01234567"
    report = _valid_report(data)
    del report["file"]["hashes"]["size"]
    with pytest.raises(ReportValidationError) as caught:
        validate_report(report, artifact_data=data)
    assert any(issue.path == "$.file.hashes.size" for issue in caught.value.issues)
