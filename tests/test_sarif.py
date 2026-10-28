import hashlib
import json

from siglens.sarif import build_sarif, save_sarif


def _report() -> dict:
    data = b"sample"
    return {
        "schema": "siglens-report/v1",
        "schema_version": "1.0.0",
        "report_type": "artifact_analysis",
        "generated_at": "2026-10-28T12:00:00+00:00",
        "tool": {"name": "SigLens", "version": "2.0.0"},
        "file": {
            "path": "C:\\Samples\\sample.exe",
            "hashes": {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        },
        "ghidra_locations": [{
            "classification": "EXACT_MATCH",
            "confidence": 1.0,
            "file_offset": 2,
            "file_offset_hex": "0x2",
            "range_start": 2,
            "range_end": 5,
            "rva": 0x1002,
            "va": 0x401002,
            "section": ".text",
            "note": "Exact offset emitted by YARA.",
            "provenance": {"type": "yara", "rule": "ExactRule"},
        }],
        "multiav": {"results": [{
            "name": "Lab AV",
            "status": "detected",
            "signature": "Lab.Signature",
        }]},
        "amsi": {"status": "clean"},
    }


def test_builds_sarif_with_byte_locations_and_fingerprints(tmp_path):
    report = _report()
    document = build_sarif(report)
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["artifacts"][0]["location"]["uri"] == "C:/Samples/sample.exe"
    assert run["artifacts"][0]["hashes"]["sha-256"] == report["file"]["hashes"]["sha256"]
    assert {result["ruleId"] for result in run["results"]} == {"YARA/ExactRule", "AV/Lab_AV"}
    yara_result = next(result for result in run["results"] if result["ruleId"] == "YARA/ExactRule")
    region = yara_result["locations"][0]["physicalLocation"]["region"]
    assert region == {"byteOffset": 2, "byteLength": 3}
    assert len(yara_result["partialFingerprints"]["siglens/v1"]) == 64

    output = save_sarif(report, tmp_path / "results.sarif")
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["$schema"].endswith("sarif-2.1.0.json")
    assert "schema_version" not in saved


def test_sarif_fingerprints_are_deterministic():
    first = build_sarif(_report())
    second = build_sarif(_report())
    assert first == second
