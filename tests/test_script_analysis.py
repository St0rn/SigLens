from pathlib import Path
from siglens.script_analysis import detect_encoding, analyze_script

def test_encoding_utf8_bom():
    assert detect_encoding(b"\xef\xbb\xbfWrite-Host test")["display"] == "UTF-8 BOM"

def test_encoding_utf16le_bom():
    raw = b"\xff\xfe" + "Write-Host test".encode("utf-16-le")
    assert detect_encoding(raw)["encoding"] == "utf-16-le"

def test_powershell_structural_candidate_without_real_amsi(monkeypatch):
    import siglens.script_analysis as sa
    monkeypatch.setattr(sa, "_powershell_ast", lambda path: None)
    data = b"function Get-A { Write-Host 'ok' }\nfunction Invoke-B { Invoke-Expression $x }\nGet-A\n"
    result = analyze_script(Path("sample.ps1"), data, amsi_result={"status":"detected"})
    assert result["classification"] in {"CANDIDATE_REGION", "MULTIPLE_CANDIDATE_REGIONS"}
    assert any("Invoke-B" in r["label"] for r in result["regions"])
    assert result["candidate_regions"]

def test_context_dependent(monkeypatch):
    import siglens.script_analysis as sa
    monkeypatch.setattr(sa, "_powershell_ast", lambda path: None)
    data = b"function A { Write-Host 'hello' }\nA\n"
    result = analyze_script(Path("sample.ps1"), data, amsi_result={"status":"detected"})
    assert result["classification"] == "CONTEXT_DEPENDENT"

def test_clean_classification():
    result = analyze_script(Path("sample.js"), b"WScript.Echo('hello');", amsi_result={"status":"clean"})
    assert result["classification"] == "AMSI_CLEAN"
