import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from siglens.source_attribution import (
    attribute_source_locations,
    load_source_map,
    parse_msvc_map,
    resolve_linker_map,
    search_source_symbol,
)


def _source_map(data: bytes) -> dict:
    return {
        "schema": "siglens-source-map/v1",
        "artifact_sha256": hashlib.sha256(data).hexdigest(),
        "language": "csharp",
        "entries": [{
            "file_offset_start": 2,
            "file_offset_end": 5,
            "symbol": "Demo.Program.Run",
            "source_file": "Program.cs",
            "source_start_line": 3,
            "source_end_line": 4,
            "language": "csharp",
        }],
    }


def test_attributes_location_to_verified_csharp_source(tmp_path):
    data = b"0123456789"
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(data)
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "Program.cs").write_text(
        "namespace Demo;\nclass Program {\n  void Run() {\n  }\n}\n",
        encoding="utf-8",
    )
    report = {
        "file": {"path": str(artifact), "hashes": {
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        }},
        "ghidra_locations": [{
            "classification": "EXACT_MATCH",
            "confidence": 1.0,
            "file_offset": 2,
            "file_offset_hex": "0x2",
            "rva": None,
            "rva_hex": None,
            "va": None,
            "va_hex": None,
            "section": None,
            "ghidra_go_to": None,
            "provenance": {"type": "yara", "rule": "ExactRule"},
        }],
    }
    result = attribute_source_locations(
        artifact,
        data,
        report,
        source_map=_source_map(data),
        source_root=source_root,
        context_lines=1,
    )
    attribution = result["attributions"][0]
    assert attribution["attribution_confidence"] == "high"
    assert attribution["primary_source"]["symbol"] == "Demo.Program.Run"
    assert attribution["primary_source"]["resolved_source_file"].endswith("Program.cs")
    assert [row["line"] for row in attribution["primary_source"]["context"]] == [2, 3, 4, 5]
    assert result["summary"] == {
        "location_count": 1,
        "resolved_count": 1,
        "high_confidence_count": 1,
    }
    assert result["ghidra_locations"] == report["ghidra_locations"]

    schema_path = Path(__file__).parents[1] / "schemas" / "siglens-report-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def test_source_map_hash_is_bound_to_artifact(tmp_path):
    path = tmp_path / "map.json"
    path.write_text(json.dumps(_source_map(b"original")), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_source_map(path, b"different")


def test_source_map_contract_is_machine_validated():
    schema_path = Path(__file__).parents[1] / "schemas" / "siglens-source-map-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_source_map(b"artifact"))


def test_parses_msvc_map_and_finds_source_declaration(tmp_path):
    linker_map = tmp_path / "sample.map"
    linker_map.write_text(
        " 0001:00000010 ?Run@Test@@QEAAXXZ 0000000140001010 f test.obj\n",
        encoding="utf-8",
    )
    entries = parse_msvc_map(linker_map)
    resolved = resolve_linker_map(0x140001018, entries)
    assert resolved["symbol"] == "?Run@Test@@QEAAXXZ"
    assert resolved["displacement"] == 8

    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "test.cpp").write_text("void Test::Run() {}\n", encoding="utf-8")
    matches = search_source_symbol(source_root, resolved["symbol"])
    assert len(matches) == 1
    assert matches[0]["source_line"] == 1
