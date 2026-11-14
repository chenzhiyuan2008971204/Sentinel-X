"""Minimal ctypes binding to the Windows Event Log API (wevtapi.dll).

Used instead of `wevtutil`, whose console output is converted to the ANSI code page and
loses characters (paths with characters outside it would no longer match scanned files).
Read-only: only EvtQuery / EvtNext / EvtRender / EvtClose are used.
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes

log = logging.getLogger(__name__)

ERROR_NO_MORE_ITEMS = 259
ERROR_ACCESS_DENIED = 5
ERROR_EVT_CHANNEL_NOT_FOUND = 15007
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_TIMEOUT = 1460

EvtQueryChannelPath = 0x1
EvtQueryForwardDirection = 0x100
EvtQueryReverseDirection = 0x200
EvtRenderEventXml = 1

_api = ctypes.WinDLL("wevtapi", use_last_error=True)
EVT_HANDLE = ctypes.c_void_p
_api.EvtQuery.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
_api.EvtQuery.restype = EVT_HANDLE
_api.EvtNext.argtypes = [EVT_HANDLE, wintypes.DWORD, ctypes.POINTER(EVT_HANDLE), wintypes.DWORD, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD)]
_api.EvtNext.restype = wintypes.BOOL
_api.EvtRender.argtypes = [EVT_HANDLE, EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
_api.EvtRender.restype = wintypes.BOOL
_api.EvtClose.argtypes = [EVT_HANDLE]
_api.EvtClose.restype = wintypes.BOOL


class EventLogError(OSError):
    def __init__(self, code: int, where: str) -> None:
        super().__init__(code, f"{where}: WinError {code}")
        self.code = code


def _render(h: int) -> str:
    used = wintypes.DWORD(0)
    props = wintypes.DWORD(0)
    _api.EvtRender(None, h, EvtRenderEventXml, 0, None, ctypes.byref(used), ctypes.byref(props))
    err = ctypes.get_last_error()
    if err != ERROR_INSUFFICIENT_BUFFER:
        raise EventLogError(err, "EvtRender(size)")
    buf = ctypes.create_string_buffer(used.value)
    if not _api.EvtRender(None, h, EvtRenderEventXml, used.value, buf, ctypes.byref(used), ctypes.byref(props)):
        raise EventLogError(ctypes.get_last_error(), "EvtRender")
    return buf.raw[: used.value].decode("utf-16-le", "replace").rstrip("\x00")


def query_xml(channel: str, xpath: str = "*", *, reverse: bool = False, max_events: int = 500) -> list[str]:
    """Return up to `max_events` events of `channel` matching `xpath`, as XML strings."""
    flags = EvtQueryChannelPath | (EvtQueryReverseDirection if reverse else EvtQueryForwardDirection)
    q = _api.EvtQuery(None, channel, xpath, flags)
    if not q:
        raise EventLogError(ctypes.get_last_error(), "EvtQuery")
    out: list[str] = []
    try:
        arr = (EVT_HANDLE * 64)()
        while len(out) < max_events:
            returned = wintypes.DWORD(0)
            want = min(64, max_events - len(out))
            if not _api.EvtNext(q, want, arr, 1000, 0, ctypes.byref(returned)):
                err = ctypes.get_last_error()
                if err in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT):
                    break
                raise EventLogError(err, "EvtNext")
            for i in range(returned.value):
                # Every returned handle is closed, and one event that cannot be rendered is
                # skipped instead of failing (and stalling) the whole channel.
                try:
                    out.append(_render(arr[i]))
                except EventLogError as exc:
                    log.warning("event not rendered", extra={"ctx": {"channel": channel, "code": exc.code}})
                finally:
                    _api.EvtClose(arr[i])
    finally:
        _api.EvtClose(q)
    return out
