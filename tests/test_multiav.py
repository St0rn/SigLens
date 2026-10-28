import sys
from siglens.multiav import _extract_regex, normalize_result, scan_cli

def test_extract_signature_named_group():
    text = "x.exe: Win.Test.Sample FOUND"
    sig = _extract_regex(r":\s*(?P<signature>.+?)\s+FOUND", text)
    assert sig == "Win.Test.Sample"

def test_normalize_result():
    r = normalize_result("Test", {"returncode": 0, "stdout": "clean"}, engine_type="cli", status="clean")
    assert r["status"] == "clean"
    assert r["whole_file_only"] is True


def test_cli_timeout_is_error_not_unavailable(monkeypatch, tmp_path):
    import siglens.multiav as multiav

    monkeypatch.setattr(
        multiav,
        "run_command",
        lambda args, timeout: {
            "error": "Command timed out after 1 seconds",
            "timed_out": True,
            "timeout_seconds": 1,
            "duration_ms": 1000.0,
            "returncode": None,
            "stdout": "clean",
            "stderr": "",
            "args": args,
        },
    )
    result = scan_cli(
        {
            "name": "Slow scanner",
            "argv": [sys.executable, "{file}"],
            "clean_regex": "clean",
            "timeout": 1,
        },
        tmp_path / "sample.bin",
    )
    assert result["status"] == "error"
    assert result["available"] is True
    assert result["timed_out"] is True


def test_cli_invalid_regex_is_config_error(tmp_path):
    result = scan_cli(
        {
            "name": "Broken adapter",
            "argv": [sys.executable, "{file}"],
            "detect_regex": "(",
        },
        tmp_path / "sample.bin",
    )
    assert result["status"] == "error"
    assert result["available"] is True
    assert "Invalid detect_regex" in result["config_error"]


def test_cli_invalid_timeout_is_config_error(tmp_path):
    result = scan_cli(
        {
            "name": "Broken timeout",
            "argv": [sys.executable, "{file}"],
            "timeout": 0,
        },
        tmp_path / "sample.bin",
    )
    assert result["status"] == "error"
    assert "Invalid timeout" in result["config_error"]
