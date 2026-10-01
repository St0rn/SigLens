from __future__ import annotations

from pathlib import Path
import os


def normalize_path(path: str | os.PathLike[str] | Path) -> Path:
    """Normalize a user-supplied path without relying on the process CWD quirks.

    PowerShell normally removes wrapping quotes, but accepting them here makes CLI use
    more robust when paths are forwarded by wrappers or copied from logs.
    """
    raw = os.fspath(path)
    if not isinstance(raw, str):
        raw = os.fsdecode(raw)
    if "\x00" in raw:
        raise ValueError("The path contains a NUL character")

    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        raw = raw[1:-1]

    raw = os.path.expandvars(os.path.expanduser(raw))
    raw = os.path.abspath(os.path.normpath(raw))
    return Path(raw)


def _read_bytes_win32(path: Path) -> bytes:
    """Read a file with CreateFileW/ReadFile.

    This bypasses Python's CRT path opening layer and also requests permissive sharing
    so a scanner/indexer holding the file does not unnecessarily prevent analysis.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    CreateFileW.restype = wintypes.HANDLE

    GetFileSizeEx = kernel32.GetFileSizeEx
    GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    GetFileSizeEx.restype = wintypes.BOOL

    ReadFile = kernel32.ReadFile
    ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    ReadFile.restype = wintypes.BOOL

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    handle = CreateFileW(
        str(path), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise OSError(err, ctypes.FormatError(err), str(path))

    try:
        size = ctypes.c_longlong(0)
        if not GetFileSizeEx(handle, ctypes.byref(size)):
            err = ctypes.get_last_error()
            raise OSError(err, ctypes.FormatError(err), str(path))
        if size.value < 0:
            raise OSError("Invalid file size")

        remaining = int(size.value)
        chunks: list[bytes] = []
        chunk_size = 1024 * 1024
        while remaining:
            want = min(chunk_size, remaining)
            buf = ctypes.create_string_buffer(want)
            got = wintypes.DWORD(0)
            if not ReadFile(handle, buf, want, ctypes.byref(got), None):
                err = ctypes.get_last_error()
                raise OSError(err, ctypes.FormatError(err), str(path))
            if got.value == 0:
                break
            chunks.append(buf.raw[: got.value])
            remaining -= got.value
        return b"".join(chunks)
    finally:
        CloseHandle(handle)


def read_file_bytes(path: str | os.PathLike[str] | Path) -> tuple[Path, bytes, dict]:
    """Read bytes with normal Python I/O then a Win32 fallback on Windows.

    Returns (normalized_path, data, io_metadata).
    """
    p = normalize_path(path)
    meta = {
        "input": os.fspath(path),
        "normalized": str(p),
        "method": None,
        "python_error": None,
        "win32_error": None,
    }

    try:
        with open(p, "rb") as f:
            data = f.read()
        meta["method"] = "python_open"
        return p, data, meta
    except OSError as exc:
        meta["python_error"] = f"{type(exc).__name__}: {exc}"
        if os.name != "nt":
            exc.siglens_io = meta  # type: ignore[attr-defined]
            raise

    try:
        data = _read_bytes_win32(p)
        meta["method"] = "CreateFileW"
        return p, data, meta
    except OSError as exc:
        meta["win32_error"] = f"{type(exc).__name__}: {exc}"
        exc.siglens_io = meta  # type: ignore[attr-defined]
        raise


def path_diagnostics(path: str | os.PathLike[str] | Path) -> dict:
    try:
        p = normalize_path(path)
    except Exception as exc:
        return {"input": repr(os.fspath(path)), "normalize_error": str(exc)}

    out = {
        "input_repr": repr(os.fspath(path)),
        "normalized": str(p),
        "cwd": os.getcwd(),
        "exists": False,
        "is_file": False,
        "is_dir": False,
        "parent_exists": p.parent.exists(),
    }
    try:
        out["exists"] = p.exists()
        out["is_file"] = p.is_file()
        out["is_dir"] = p.is_dir()
        if p.exists():
            st = p.stat()
            out["size"] = st.st_size
            out["mode"] = oct(st.st_mode)
    except Exception as exc:
        out["stat_error"] = f"{type(exc).__name__}: {exc}"
    return out
