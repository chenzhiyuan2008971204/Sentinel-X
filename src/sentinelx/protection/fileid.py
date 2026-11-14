"""A file's content "stamp": size, last-write time and Windows' change time (engineering audit 8, L2).

Size and last-write time alone can be kept the same by a program that changes a file's content
and then sets the old time again (SetFileTime). Windows' ChangeTime cannot be set that way by
ordinary programs and moves on every write, so a stamp with it notices such a change. It also
also moves when Windows stores information about a file (for example the first time a
program runs) or its permissions change, so a different change time alone is checked by
comparing the content's SHA-256 with the scanned one. Limit: Windows updates file times in
ticks of about 16 ms, so two changes within one tick look the same.
"""

from __future__ import annotations

import hashlib
import os
import sys

Stamp = tuple[int, int, int]


_api = None  # (kernel32, FileBasicInfo type, invalid handle value), prepared once


def _win_api():  # type: ignore[no-untyped-def]
    """Structure type and function signatures, made once: this runs for every file event, and
    making them per call cost a new ctypes class each time (engineering audit 8, M4)."""
    global _api
    if _api is None:
        import ctypes
        from ctypes import wintypes

        class FileBasicInfo(ctypes.Structure):
            _fields_ = [("CreationTime", ctypes.c_longlong), ("LastAccessTime", ctypes.c_longlong),
                        ("LastWriteTime", ctypes.c_longlong), ("ChangeTime", ctypes.c_longlong),
                        ("FileAttributes", wintypes.DWORD)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        _api = (k32, FileBasicInfo, wintypes.HANDLE(-1).value)
    return _api


def _change_time(path: str) -> int | None:
    if sys.platform != "win32":
        return None
    import ctypes

    k32, FileBasicInfo, invalid = _win_api()
    # FILE_READ_ATTRIBUTES, share read/write/delete, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS
    h = k32.CreateFileW(path, 0x80, 0x7, None, 3, 0x02000000, None)
    if h in (None, invalid):
        return None
    try:
        info = FileBasicInfo()
        if not k32.GetFileInformationByHandleEx(h, 0, ctypes.byref(info), ctypes.sizeof(info)):  # FileBasicInfo
            return None
        return int(info.ChangeTime)
    finally:
        k32.CloseHandle(h)


def stamp(path: str) -> Stamp | None:
    """(size, last-write ns, change time) or None if the file cannot be read."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    ct = _change_time(path)
    return st.st_size, st.st_mtime_ns, ct if ct is not None else getattr(st, "st_ctime_ns", 0)


def sha256(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()
