import json
from pathlib import Path
from threading import Event

import pytest
from jsonschema import Draft202012Validator

from siglens.analysis import AnalysisCancelled, AnalysisOptions, analyze_artifact
from siglens.report import REPORT_SCHEMA_ID, REPORT_SCHEMA_VERSION, save_json


def test_reusable_analysis_and_versioned_report(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("https://example.org/path", encoding="utf-8")
    result = analyze_artifact(sample, AnalysisOptions(extract_iocs=True))
    assert result.report["schema"] == REPORT_SCHEMA_ID
    assert result.report["schema_version"] == REPORT_SCHEMA_VERSION
    assert result.report["file"]["hashes"]["size"] == sample.stat().st_size
    assert "https://example.org/path" in result.report["iocs"]["urls"]

    output = tmp_path / "report.json"
    save_json(result.report, output)
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["report_type"] == "artifact_analysis"
    schema_path = Path(__file__).parents[1] / "schemas" / "siglens-report-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(saved)


def test_analysis_honors_preexisting_cancellation(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    cancelled = Event()
    cancelled.set()
    with pytest.raises(AnalysisCancelled):
        analyze_artifact(sample, cancel_event=cancelled)
