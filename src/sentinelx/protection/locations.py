"""Where real-time protection looks: the user's known folders and removable drives.

Known folders are resolved with SHGetKnownFolderPath, not built from the user name, because
users (and OneDrive) move Desktop, Documents and Downloads.
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
import threading
import time
import uuid
from ctypes import wintypes
from pathlib import Path

import psutil

FOLDERID_DOWNLOADS = uuid.UUID("374DE290-123F-4565-9164-39C4925E467B")
FOLDERID_DESKTOP = uuid.UUID("B4BFCC3A-DB2C-424C-B029-7FE99A87C641")
FOLDERID_DOCUMENTS = uuid.UUID("FDD39AD0-238F-46AF-ADB4-6C85480369C7")

# The user's real temporary folder, captured at import time: the app later points its own
# temporary files elsewhere so that protection does not scan them.
USER_TEMP = Path(os.environ.get("TEMP") or tempfile.gettempdir())


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


_get_known_folder = None  # SHGetKnownFolderPath, prepared once
# Folder lookups are asked for every file event (is it in Downloads, Desktop or Documents?).
# Remembered briefly: users (and OneDrive) can move these folders, so not forever.
KNOWN_FOLDER_TTL_S = 30.0
_known_cache: dict[uuid.UUID, tuple[float, Path | None]] = {}
_known_lock = threading.Lock()


def _lookup_known_folder(folder_id: uuid.UUID) -> Path | None:
    # The structure type and the function signature are made once. Defining the structure class
    # inside this function (as before 0.16.0 final) made a new class per call, and ctypes keeps
    # every POINTER(class) it creates for good: about 1.5 KB per call, six calls per file event.
    # Measured: 20,000 new files raised memory from 56 MB to 514 MB (engineering audit 8, M4).
    global _get_known_folder
    if _get_known_folder is None:
        fn = ctypes.WinDLL("shell32").SHGetKnownFolderPath
        fn.argtypes = [ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
        fn.restype = ctypes.c_long
        _get_known_folder = fn
    g = _GUID.from_buffer_copy(folder_id.bytes_le)
    out = ctypes.c_wchar_p()
    if _get_known_folder(ctypes.byref(g), 0, None, ctypes.byref(out)) != 0:
        return None
    try:
        return Path(out.value) if out.value else None
    finally:
        ctypes.windll.ole32.CoTaskMemFree(out)


def known_folder(folder_id: uuid.UUID, *, now: float | None = None) -> Path | None:
    if sys.platform != "win32":
        return None
    t = time.monotonic() if now is None else now
    with _known_lock:
        hit = _known_cache.get(folder_id)
        if hit is not None and t - hit[0] < KNOWN_FOLDER_TTL_S:
            return hit[1]
    path = _lookup_known_folder(folder_id)
    with _known_lock:
        _known_cache[folder_id] = (t, path)
    return path


def downloads() -> Path | None:
    return known_folder(FOLDERID_DOWNLOADS)


def removable_drives() -> list[Path]:
    """Mounted removable drives (USB sticks, SD cards). Network and fixed drives are excluded."""
    out = []
    for part in psutil.disk_partitions(all=False):
        if "removable" in part.opts.lower() and os.path.isdir(part.mountpoint):
            out.append(Path(part.mountpoint))
    return out


def watched_folders(*, downloads_: bool, desktop_documents: bool, temp: bool) -> list[tuple[str, Path]]:
    """(label, folder) for the enabled fixed locations that exist."""
    found: list[tuple[str, Path | None]] = []
    if downloads_:
        found.append(("下載", downloads()))
    if desktop_documents:
        found.append(("桌面", known_folder(FOLDERID_DESKTOP)))
        found.append(("文件", known_folder(FOLDERID_DOCUMENTS)))
    if temp:
        found.append(("暫存", USER_TEMP))
    seen: set[str] = set()
    out = []
    for label, p in found:
        if p is not None and p.is_dir() and str(p).lower() not in seen:
            seen.add(str(p).lower())
            out.append((label, p))
    return out


def fixed_drives() -> list[Path]:
    """Mounted local hard drives (C:\\, D:\\ ...). Network, optical and removable drives are excluded."""
    out = []
    for part in psutil.disk_partitions(all=False):
        opts = part.opts.lower()
        if "fixed" in opts and "removable" not in opts and os.path.isdir(part.mountpoint):
            out.append(Path(part.mountpoint))
    return out


def desktop() -> Path | None:
    return known_folder(FOLDERID_DESKTOP)


def documents() -> Path | None:
    return known_folder(FOLDERID_DOCUMENTS)


# Paths that change all the time and are not where new threats arrive, or are covered by
# Windows itself. Skipping them keeps whole-drive watching from slowing the computer down.
_WINDIR = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")).rstrip("\\")
NOISY_PARTS = (
    "\\system volume information\\", "\\$recycle.bin\\", "\\$windows.~bt\\", "\\$windows.~ws\\",
    "\\programdata\\microsoft\\windows defender\\", "\\programdata\\mcafee\\",
    "\\programdata\\microsoft\\search\\", "\\programdata\\microsoft\\diagnosis\\",
    "\\programdata\\microsoft\\windows\\wer\\",
    "\\appdata\\local\\packages\\", "\\appdata\\local\\microsoft\\windows\\inetcache\\",
    "\\appdata\\local\\microsoft\\windows\\explorer\\", "\\appdata\\local\\connecteddevicesplatform\\",
    "\\cache\\cache_data\\", "\\code cache\\", "\\gpucache\\", "\\shadercache\\", "\\dawngraphitecache\\",
    "\\service worker\\cachestorage\\", "\\service worker\\scriptcache\\",
    "\\.virtualbox\\", "\\virtualbox vms\\", "\\sentinelx-sandbox\\", "\\.git\\objects\\",
)
NOISY_SUFFIXES = frozenset({".etl", ".evtx", ".db-wal", ".db-shm", ".db-journal", ".sqlite-wal", ".sqlite-shm",
                            ".ldb", ".log", ".blf", ".regtrans-ms", ".pf", ".lock", ".vdi", ".vmdk", ".vhd", ".vhdx",
                            ".sav", ".nvram"})
NOISY_NAMES = frozenset({"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp", "cookies",
                         "cookies-journal", "history", "history-journal", "current session", "current tabs",
                         "web data", "login data", "network persistent state", "transportsecurity",
                         "ntuser.dat", "usrclass.dat"})


def noisy(path: str) -> bool:
    """True for paths whole-drive protection skips (see NOISY_* above)."""
    n = os.path.normcase(path)
    if n.startswith(_WINDIR + "\\") and not n.startswith(_WINDIR + "\\temp\\"):
        return True  # Windows' own files: protected by Windows; its Temp folder is still checked
    name = os.path.basename(n)
    if name in NOISY_NAMES or os.path.splitext(name)[1] in NOISY_SUFFIXES:
        return True
    return any(part in n for part in NOISY_PARTS)
