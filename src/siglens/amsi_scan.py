from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import os
import sys

AMSI_RESULT_CLEAN = 0
AMSI_RESULT_NOT_DETECTED = 1
AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000
AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4FFF
AMSI_RESULT_DETECTED = 0x8000


def _result_name(value: int) -> str:
    if value >= AMSI_RESULT_DETECTED:
        return 'AMSI_RESULT_DETECTED'
    if AMSI_RESULT_BLOCKED_BY_ADMIN_START <= value <= AMSI_RESULT_BLOCKED_BY_ADMIN_END:
        return 'AMSI_RESULT_BLOCKED_BY_ADMIN'
    if value == AMSI_RESULT_CLEAN:
        return 'AMSI_RESULT_CLEAN'
    if value == AMSI_RESULT_NOT_DETECTED:
        return 'AMSI_RESULT_NOT_DETECTED'
    return 'AMSI_RESULT_UNKNOWN'


def _classification(value: int) -> str:
    if value >= AMSI_RESULT_DETECTED:
        return "detected"
    if AMSI_RESULT_BLOCKED_BY_ADMIN_START <= value <= AMSI_RESULT_BLOCKED_BY_ADMIN_END:
        return "blocked_by_admin"
    if value == AMSI_RESULT_CLEAN:
        return "clean"
    if value == AMSI_RESULT_NOT_DETECTED:
        return "not_detected"
    return "unknown"


def scan_buffer(data: bytes, content_name: str = "SigLens buffer") -> dict:
    if os.name != "nt":
        return {"available": False, "status": "unsupported", "error": "AMSI is only available on Windows."}

    amsi = ctypes.WinDLL("amsi.dll")
    HAMSICONTEXT = ctypes.c_void_p
    HAMSISESSION = ctypes.c_void_p
    HRESULT = ctypes.c_long
    AMSI_RESULT = ctypes.c_uint

    amsi.AmsiInitialize.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(HAMSICONTEXT)]
    amsi.AmsiInitialize.restype = HRESULT
    amsi.AmsiUninitialize.argtypes = [HAMSICONTEXT]
    amsi.AmsiUninitialize.restype = None
    amsi.AmsiOpenSession.argtypes = [HAMSICONTEXT, ctypes.POINTER(HAMSISESSION)]
    amsi.AmsiOpenSession.restype = HRESULT
    amsi.AmsiCloseSession.argtypes = [HAMSICONTEXT, HAMSISESSION]
    amsi.AmsiCloseSession.restype = None
    amsi.AmsiScanBuffer.argtypes = [
        HAMSICONTEXT, ctypes.c_void_p, wintypes.ULONG,
        wintypes.LPCWSTR, HAMSISESSION, ctypes.POINTER(AMSI_RESULT)
    ]
    amsi.AmsiScanBuffer.restype = HRESULT

    ctx = HAMSICONTEXT()
    hr = amsi.AmsiInitialize("SigLens by St0rn / CybersecurIT", ctypes.byref(ctx))
    if hr != 0:
        return {"available": True, "status": "error", "hresult": int(hr), "error": "AmsiInitialize failed."}

    session = HAMSISESSION()
    opened = False
    try:
        hr_session = amsi.AmsiOpenSession(ctx, ctypes.byref(session))
        opened = (hr_session == 0)

        if not data:
            buf = ctypes.create_string_buffer(b"\x00")
            length = 0
        else:
            buf = ctypes.create_string_buffer(data, len(data))
            length = len(data)

        result = AMSI_RESULT()
        hr_scan = amsi.AmsiScanBuffer(
            ctx,
            ctypes.cast(buf, ctypes.c_void_p),
            length,
            content_name,
            session if opened else HAMSISESSION(),
            ctypes.byref(result),
        )
        if hr_scan != 0:
            return {
                "available": True,
                "status": "error",
                "hresult": int(hr_scan),
                "error": "AmsiScanBuffer failed.",
            }

        value = int(result.value)
        return {
            "available": True,
            "status": _classification(value),
            "result": value,
            "result_name": _result_name(value),
            "content_name": content_name,
            "length": length,
            "whole_buffer_only": True,
        }
    finally:
        if opened:
            amsi.AmsiCloseSession(ctx, session)
        amsi.AmsiUninitialize(ctx)


def scan_file(path: Path) -> dict:
    data = path.read_bytes()
    return scan_buffer(data, str(path))
