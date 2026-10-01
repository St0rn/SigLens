from pathlib import Path
from siglens.utils import entropy
from siglens.compare import changed_ranges

def test_entropy_zero():
    assert entropy(b"") == 0.0

def test_changed_ranges():
    a = b"AAAA1111BBBB"
    b = b"AAAA2222BBBB"
    r = changed_ranges(a, b)
    assert r[0]["start"] == 4
    assert r[0]["end"] == 8
