from pathlib import Path
from siglens.fileio import normalize_path, read_file_bytes, path_diagnostics


def test_read_file_bytes(tmp_path: Path):
    p = tmp_path / "file with spaces.bin"
    p.write_bytes(b"abc123")
    np, data, meta = read_file_bytes(p)
    assert data == b"abc123"
    assert np.exists()
    assert meta["method"] == "python_open"


def test_wrapping_quotes_are_accepted(tmp_path: Path):
    p = tmp_path / "quoted.bin"
    p.write_bytes(b"x")
    wrapped = f'"{p}"'
    np, data, _ = read_file_bytes(wrapped)
    assert data == b"x"
    assert np.name == "quoted.bin"


def test_path_diagnostics(tmp_path: Path):
    p = tmp_path / "d.bin"
    p.write_bytes(b"hello")
    d = path_diagnostics(p)
    assert d["exists"] is True
    assert d["is_file"] is True
    assert d["size"] == 5
