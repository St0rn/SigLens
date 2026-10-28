import pytest
from pathlib import Path
from siglens.window_scan import fixed_windows, MIN_WINDOW_KIB, window_scan

def test_default_minimum_windows():
    data = b"A" * (300 * 1024)
    rows = fixed_windows(data, window_kib=256)
    assert len(rows) == 2
    assert rows[0]["offset"] == 0
    assert rows[0]["end"] == 256 * 1024
    assert rows[1]["offset"] == 256 * 1024
    assert rows[1]["end"] == 300 * 1024

def test_rejects_below_minimum():
    with pytest.raises(ValueError):
        fixed_windows(b"A" * 1024, window_kib=MIN_WINDOW_KIB - 1)

def test_sha256_present():
    rows = fixed_windows(b"A" * (256 * 1024), window_kib=256)
    assert len(rows[0]["sha256"]) == 64


def test_non_monotonic_prefixes_are_context_dependent(monkeypatch, tmp_path):
    import siglens.window_scan as window_scan_module

    def fake_scan(path, config_path):
        size = Path(path).stat().st_size
        status = "clean" if size == 8 else "detected"
        return {"results": [{"name": "Mock", "status": status}], "summary": {}}

    monkeypatch.setattr(window_scan_module, "scan_engines", fake_scan)
    data = b"A" * 16
    result = window_scan(
        tmp_path / "sample.bin",
        tmp_path / "engines.json",
        data,
        stability_attempts=3,
        non_monotonic_probes=3,
        max_windows=100,
    )
    assert result["classification"] == "CONTEXT_DEPENDENT"
    assert result["candidates"][0]["non_monotonic_evidence"]


def test_repeated_prefix_disagreement_is_context_dependent(monkeypatch, tmp_path):
    import siglens.window_scan as window_scan_module

    calls = 0

    def fake_scan(path, config_path):
        nonlocal calls
        calls += 1
        status = "clean" if calls == 2 else "detected"
        return {"results": [{"name": "Mock", "status": status}], "summary": {}}

    monkeypatch.setattr(window_scan_module, "scan_engines", fake_scan)
    result = window_scan(
        tmp_path / "sample.bin",
        tmp_path / "engines.json",
        b"A" * 16,
        stability_attempts=3,
        non_monotonic_probes=0,
        max_windows=20,
    )
    assert result["classification"] == "CONTEXT_DEPENDENT"
    assert result["candidates"][0]["stability"]["unstable"] is True
