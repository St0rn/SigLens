from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .report import REPORT_SCHEMA_ID


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


class ReportValidationError(ValueError):
    def __init__(self, issues: list[ValidationIssue]):
        self.issues = issues
        super().__init__("; ".join(str(issue) for issue in issues))


def _schema_candidates() -> list[Path]:
    candidates = [
        Path(__file__).resolve().parents[2] / "schemas" / "siglens-report-v1.schema.json",
        Path(sys.prefix) / "share" / "siglens" / "schemas" / "siglens-report-v1.schema.json",
    ]
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        candidates.insert(0, Path(bundle_root) / "schemas" / "siglens-report-v1.schema.json")
    return candidates


def report_schema_path() -> Path:
    for candidate in _schema_candidates():
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(path) for path in _schema_candidates())
    raise FileNotFoundError(f"SigLens report schema was not found (searched: {searched})")


def load_report(path: Path) -> dict:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    payload = json.loads(
        path.read_text(encoding="utf-8-sig"),
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(payload, dict):
        raise ValueError("Report JSON root must be an object")
    return payload


def _json_path(parts: list[Any]) -> str:
    if not parts:
        return "$"
    value = "$"
    for part in parts:
        value += f"[{part}]" if isinstance(part, int) else f".{part}"
    return value


def _semantic_issues(report: dict, artifact_data: bytes | None) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    locations = report.get("ghidra_locations", [])
    if not isinstance(locations, list):
        locations = []

    expected_size = report.get("file", {}).get("hashes", {}).get("size")
    effective_size = len(artifact_data) if artifact_data is not None else expected_size

    for index, location in enumerate(locations):
        if not isinstance(location, dict):
            continue
        prefix = f"$.ghidra_locations[{index}]"
        offset = location.get("file_offset")
        if type(offset) is int and type(effective_size) is int and offset >= effective_size:
            issues.append(ValidationIssue(f"{prefix}.file_offset", "offset is outside the artifact"))

        start = location.get("range_start")
        end = location.get("range_end")
        if type(start) is int and type(end) is int and end < start:
            issues.append(ValidationIssue(f"{prefix}.range_end", "range end precedes range start"))
        if type(start) is int and type(effective_size) is int and start > effective_size:
            issues.append(ValidationIssue(f"{prefix}.range_start", "range starts beyond the artifact"))
        if type(end) is int and type(effective_size) is int and end > effective_size:
            issues.append(ValidationIssue(f"{prefix}.range_end", "range extends beyond the artifact"))
        if (
            type(offset) is int
            and type(start) is int
            and type(end) is int
            and end > start
            and not start <= offset < end
        ):
            issues.append(ValidationIssue(f"{prefix}.file_offset", "offset is outside its reported range"))

        for numeric_name, hex_name in (
            ("file_offset", "file_offset_hex"),
            ("rva", "rva_hex"),
            ("va", "va_hex"),
            ("image_base", "image_base_hex"),
        ):
            numeric = location.get(numeric_name)
            rendered = location.get(hex_name)
            if type(numeric) is int and rendered is not None:
                try:
                    matches = int(str(rendered), 0) == numeric
                except ValueError:
                    matches = False
                if not matches:
                    issues.append(ValidationIssue(f"{prefix}.{hex_name}", f"does not match {numeric_name}"))

        rva = location.get("rva")
        va = location.get("va")
        image_base = location.get("image_base")
        if all(type(value) is int for value in (rva, va, image_base)) and va != image_base + rva:
            issues.append(ValidationIssue(f"{prefix}.va", "VA does not equal image base + RVA"))

    if artifact_data is not None:
        hashes = report.get("file", {}).get("hashes", {})
        expected_hash = hashes.get("sha256") if isinstance(hashes, dict) else None
        actual_hash = hashlib.sha256(artifact_data).hexdigest()
        if not expected_hash:
            issues.append(ValidationIssue("$.file.hashes.sha256", "required for artifact verification"))
        elif str(expected_hash).lower() != actual_hash:
            issues.append(ValidationIssue("$.file.hashes.sha256", "does not match the supplied artifact"))
        if type(expected_size) is not int:
            issues.append(ValidationIssue("$.file.hashes.size", "required for artifact verification"))
        elif expected_size != len(artifact_data):
            issues.append(ValidationIssue("$.file.hashes.size", "does not match the supplied artifact"))

    return issues


def validate_report(report: dict, artifact_data: bytes | None = None) -> dict:
    schema = json.loads(report_schema_path().read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    issues = [
        ValidationIssue(_json_path(list(error.absolute_path)), error.message)
        for error in sorted(
            validator.iter_errors(report),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
    ]
    issues.extend(_semantic_issues(report, artifact_data))
    if issues:
        raise ReportValidationError(issues)

    return {
        "valid": True,
        "schema": report.get("schema"),
        "schema_supported": report.get("schema") == REPORT_SCHEMA_ID,
        "schema_version": report.get("schema_version"),
        "report_type": report.get("report_type"),
        "ghidra_location_count": len(report.get("ghidra_locations", [])),
        "artifact_verified": artifact_data is not None,
    }
