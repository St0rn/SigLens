import pytest
from siglens.window_scan import fixed_windows, MIN_WINDOW_KIB

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
