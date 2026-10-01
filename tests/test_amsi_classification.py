from siglens.amsi_scan import _classification

def test_amsi_classification():
    assert _classification(0) == "clean"
    assert _classification(1) == "not_detected"
    assert _classification(0x4000) == "blocked_by_admin"
    assert _classification(0x8000) == "detected"
