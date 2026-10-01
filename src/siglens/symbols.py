from __future__ import annotations
from pathlib import Path
import os


def resolve_with_dbghelp(image: Path, va: int, symbol_path: Path | None = None) -> dict:
    """Resolve symbol and source line on Windows using DbgHelp.

    The resolver does not download symbols. It searches the executable's directory,
    an optional user-supplied symbol directory, and normal DbgHelp local lookup paths.
    """
    result = {
        "available": os.name == "nt",
        "resolved": False,
        "symbol": None,
        "displacement": None,
        "source_file": None,
        "source_line": None,
        "error": None,
    }
    if os.name != "nt":
        result["error"] = "DbgHelp symbol resolution is available only on Windows"
        return result

    try:
        import ctypes
        from ctypes import wintypes

        dbghelp = ctypes.WinDLL("dbghelp.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")
        process = kernel32.GetCurrentProcess()

        SymInitialize = dbghelp.SymInitializeW
        SymInitialize.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        SymInitialize.restype = wintypes.BOOL

        SymCleanup = dbghelp.SymCleanup
        SymCleanup.argtypes = [wintypes.HANDLE]
        SymCleanup.restype = wintypes.BOOL

        SymSetOptions = dbghelp.SymSetOptions
        SymSetOptions.argtypes = [wintypes.DWORD]
        SymSetOptions.restype = wintypes.DWORD

        SymLoadModuleEx = dbghelp.SymLoadModuleExW
        SymLoadModuleEx.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR,
                                    wintypes.LPCWSTR, ctypes.c_ulonglong, wintypes.DWORD,
                                    wintypes.LPVOID, wintypes.DWORD]
        SymLoadModuleEx.restype = ctypes.c_ulonglong

        MAX_SYM_NAME = 1024

        class SYMBOL_INFO(ctypes.Structure):
            _fields_ = [
                ("SizeOfStruct", wintypes.ULONG),
                ("TypeIndex", wintypes.ULONG),
                ("Reserved", ctypes.c_ulonglong * 2),
                ("Index", wintypes.ULONG),
                ("Size", wintypes.ULONG),
                ("ModBase", ctypes.c_ulonglong),
                ("Flags", wintypes.ULONG),
                ("Value", ctypes.c_ulonglong),
                ("Address", ctypes.c_ulonglong),
                ("Register", wintypes.ULONG),
                ("Scope", wintypes.ULONG),
                ("Tag", wintypes.ULONG),
                ("NameLen", wintypes.ULONG),
                ("MaxNameLen", wintypes.ULONG),
                ("Name", ctypes.c_char * 1),
            ]

        class IMAGEHLP_LINE64(ctypes.Structure):
            _fields_ = [
                ("SizeOfStruct", wintypes.DWORD),
                ("Key", wintypes.LPVOID),
                ("LineNumber", wintypes.DWORD),
                ("FileName", ctypes.c_char_p),
                ("Address", ctypes.c_ulonglong),
            ]

        SymFromAddr = dbghelp.SymFromAddr
        SymFromAddr.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong,
                                ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p]
        SymFromAddr.restype = wintypes.BOOL

        SymGetLineFromAddr64 = dbghelp.SymGetLineFromAddr64
        SymGetLineFromAddr64.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong,
                                         ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(IMAGEHLP_LINE64)]
        SymGetLineFromAddr64.restype = wintypes.BOOL

        # SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS
        SymSetOptions(0x00000002 | 0x00000004 | 0x00000010 | 0x00000200)

        search_parts = [str(image.parent)]
        if symbol_path:
            search_parts.insert(0, str(symbol_path))
        search = ";".join(dict.fromkeys(search_parts))

        if not SymInitialize(process, search, False):
            raise OSError(ctypes.get_last_error(), "SymInitializeW failed")
        try:
            base = SymLoadModuleEx(process, None, str(image), None, 0, 0, None, 0)
            if not base:
                raise OSError(ctypes.get_last_error(), "SymLoadModuleExW failed")

            buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFO) + MAX_SYM_NAME)
            sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFO))
            sym.contents.SizeOfStruct = ctypes.sizeof(SYMBOL_INFO)
            sym.contents.MaxNameLen = MAX_SYM_NAME
            displacement = ctypes.c_ulonglong(0)
            if SymFromAddr(process, ctypes.c_ulonglong(va), ctypes.byref(displacement), sym):
                name_addr = ctypes.addressof(sym.contents) + SYMBOL_INFO.Name.offset
                raw = ctypes.string_at(name_addr, sym.contents.NameLen)
                result["symbol"] = raw.decode(errors="replace")
                result["displacement"] = int(displacement.value)
                result["resolved"] = True

            line = IMAGEHLP_LINE64()
            line.SizeOfStruct = ctypes.sizeof(IMAGEHLP_LINE64)
            line_disp = wintypes.DWORD(0)
            if SymGetLineFromAddr64(process, ctypes.c_ulonglong(va), ctypes.byref(line_disp), ctypes.byref(line)):
                if line.FileName:
                    result["source_file"] = line.FileName.decode(errors="replace")
                result["source_line"] = int(line.LineNumber)
                result["resolved"] = True
        finally:
            SymCleanup(process)
    except Exception as exc:
        result["error"] = str(exc)
    return result
