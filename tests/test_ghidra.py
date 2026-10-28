import hashlib
import json
from pathlib import Path

import pytest

from siglens.ghidra import (
    build_ghidra_locations,
    save_ghidra_csv,
    verify_report_artifact,
)


def _report(data: bytes) -> dict:
    return {
        "file": {"hashes": {"sha256": hashlib.sha256(data).hexdigest()}},
        "yara": {
            "matches": [{
                "rule": "ExactRule",
                "strings": [{"identifier": "$a", "offset": 2, "matched_length": 3}],
            }],
        },
        "multiav": {
            "results": [{
                "name": "Native engine",
                "signature": "Test.Signature",
                "offset": 5,
                "offset_source": "native_engine_output",
            }],
        },
        "window_scan": {
            "scan_count": 12,
            "candidates": [{
                "classification": "CANDIDATE_REGION",
                "boundary_low": 6,
                "boundary_high": 9,
                "inferred_offset": 8,
                "stability": {"confidence": 0.667},
            }],
        },
        "component_scan": {"regions": []},
    }


def test_builds_typed_ghidra_locations_and_csv(tmp_path):
    data = b"0123456789abcdef"
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(data)
    report = _report(data)
    verify_report_artifact(report, data)
    locations = build_ghidra_locations(artifact, data, report)
    assert [row["classification"] for row in locations] == [
        "EXACT_MATCH",
        "NATIVE_ENGINE_OFFSET",
        "INFERRED_BOUNDARY",
    ]
    assert locations[0]["file_offset_hex"] == "0x2"
    assert locations[2]["range_start_hex"] == "0x6"
    assert locations[2]["range_end_hex"] == "0x9"
    assert "not a native engine offset" in locations[2]["note"]

    output = save_ghidra_csv(locations, tmp_path / "ghidra.csv")
    text = output.read_text(encoding="utf-8-sig")
    assert "EXACT_MATCH" in text
    assert "0x2" in text


def test_rejects_report_for_a_different_artifact():
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_report_artifact(_report(b"original"), b"different")


def test_schema_accepts_ghidra_locations(tmp_path):
    from jsonschema import Draft202012Validator

    data = b"0123456789abcdef"
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(data)
    payload = {
        "schema": "siglens-report/v1",
        "schema_version": "1.0.0",
        "report_type": "artifact_analysis",
        "generated_at": "2026-10-28T12:00:00+00:00",
        "file": {"hashes": {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}},
        "ghidra_locations": build_ghidra_locations(artifact, data, _report(data)),
    }
    schema_path = Path(__file__).parents[1] / "schemas" / "siglens-report-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)
