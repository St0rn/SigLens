from siglens.multiav import _extract_regex, normalize_result

def test_extract_signature_named_group():
    text = "x.exe: Win.Test.Sample FOUND"
    sig = _extract_regex(r":\s*(?P<signature>.+?)\s+FOUND", text)
    assert sig == "Win.Test.Sample"

def test_normalize_result():
    r = normalize_result("Test", {"returncode": 0, "stdout": "clean"}, engine_type="cli", status="clean")
    assert r["status"] == "clean"
    assert r["whole_file_only"] is True
