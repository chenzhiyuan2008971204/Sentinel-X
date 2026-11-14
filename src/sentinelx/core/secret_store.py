"""Small per-user secrets (e.g. the VirusTotal API key) encrypted with Windows DPAPI.

CryptProtectData with the current user's credentials: only the same Windows user on the same
computer can decrypt the file. It is never written in plain text, never logged and never
shown again after it is saved (the settings page only says whether a key is stored).
DPAPI does not protect against malware already running as the same user.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

ENTROPY = b"SentinelX-secret-v1"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:  # type: ignore[type-arg]
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _call(fn_name: str, data: bytes) -> bytes:
    if sys.platform != "win32":
        raise OSError("DPAPI is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = getattr(crypt32, fn_name)
    fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.POINTER(_Blob), ctypes.c_void_p,
                   ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    fn.restype = wintypes.BOOL
    inp, _keep1 = _blob(data)
    ent, _keep2 = _blob(ENTROPY)
    out = _Blob()
    if not fn(ctypes.byref(inp), None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out)):  # UI_FORBIDDEN
        raise OSError(f"{fn_name} failed ({ctypes.get_last_error()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def protect(data: bytes) -> bytes:
    return _call("CryptProtectData", data)


def unprotect(data: bytes) -> bytes:
    return _call("CryptUnprotectData", data)


class SecretFile:
    """One secret in one file, encrypted for the current Windows user."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def exists(self) -> bool:
        return self._path.is_file()

    def save(self, value: str) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_bytes(protect(value.encode("utf-8")))
        os.replace(tmp, self._path)

    def load(self) -> str | None:
        try:
            return unprotect(self._path.read_bytes()).decode("utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError):
            return None  # unreadable or from another user: treated as "no key"

    def delete(self) -> None:
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass
