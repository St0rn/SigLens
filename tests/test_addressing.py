from siglens.functions import resolve_runtime_function


def test_non_pe_runtime_function(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")
    result = resolve_runtime_function(p, 0)
    assert result["resolved"] is False
