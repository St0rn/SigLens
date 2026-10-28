from pathlib import Path

from siglens.pe_analyzer import analyze_pe


def test_unexpected_parser_failure_is_reported(monkeypatch):
    import siglens.pe_analyzer as pe_analyzer

    def fail(**kwargs):
        raise OSError("parser failure")

    monkeypatch.setattr(pe_analyzer.pefile, "PE", fail)
    result = analyze_pe(Path("sample.exe"), b"MZ")
    assert result["is_pe"] is False
    assert result["error"] == "OSError: parser failure"
