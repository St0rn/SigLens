from siglens.correlation import correlate_offset


def test_non_pe_correlation(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abcdef")
    result = correlate_offset(p, 1)
    assert result["offset"] == 1
    assert result["address"]["mapped"] is False
