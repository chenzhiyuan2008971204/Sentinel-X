"""One Sentinel X per data folder, and the restart after a settings change.

Two windows on the same data would run two monitors (events recorded twice) and race on the
quarantine vault. A lock file in the data root is held for the life of the process; Qt's
QLockFile treats a lock left by a dead process as stale, so a crash never blocks the next
start. An instance started by the app itself (admin relaunch, restart) waits for the old
one to finish closing instead of giving up.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QLockFile

LOCK_NAME = "sentinelx.lock"
# Named mutex held while the app runs, so the installer and uninstaller (Inno Setup AppMutex)
# can refuse to replace or remove files that are in use (audit F3). Must match installer.iss.
APP_MUTEX = "SentinelX-6D1C4F2A-running"
HANDOVER_WAIT_MS = 30_000
RESTARTED_FLAG = "--restarted"


class InstanceLock:
    def __init__(self, root: Path) -> None:
        self._lock = QLockFile(str(root / LOCK_NAME))
        self._lock.setStaleLockTime(0)  # stale only when the owning process is gone
        self._mutex: int | None = None

    def acquire(self, wait_ms: int = 0) -> bool:
        if not self._lock.tryLock(wait_ms):
            return False
        self._mutex = _create_mutex(APP_MUTEX)
        return True

    def release(self) -> None:
        if self._mutex:
            _close_handle(self._mutex)
            self._mutex = None
        if self._lock.isLocked():
            self._lock.unlock()


def _create_mutex(name: str) -> int | None:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    k32.CreateMutexW.restype = wintypes.HANDLE
    h = k32.CreateMutexW(None, False, name)
    return int(h) if h else None


def _close_handle(h: int) -> None:
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32")
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle(h)


def mutex_exists(name: str = APP_MUTEX) -> bool:
    """True while some Sentinel X process holds the running mutex (used by tests)."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32")
    k32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k32.OpenMutexW.restype = wintypes.HANDLE
    h = k32.OpenMutexW(0x00100000, False, name)  # SYNCHRONIZE
    if h:
        _close_handle(h)
        return True
    return False


def restart_command(executable: str, frozen: bool) -> tuple[str, list[str]]:
    """(program, arguments) to start a fresh, unelevated copy. Fixed arguments only."""
    if frozen:
        return executable, [RESTARTED_FLAG]
    return executable, ["-m", "sentinelx", RESTARTED_FLAG]


def restart() -> bool:
    """Start a new instance (it waits for this one's lock). The caller then quits."""
    from PySide6.QtCore import QProcess

    program, args = restart_command(sys.executable, bool(getattr(sys, "frozen", False)))
    ok, _pid = QProcess.startDetached(program, args)
    return bool(ok)
