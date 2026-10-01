from siglens.region_context import hexdump


def test_hexdump_offsets():
    lines = hexdump(b"ABCD", base_offset=0x1000)
    assert lines[0].startswith("00001000")
    assert "41 42 43 44" in lines[0]
