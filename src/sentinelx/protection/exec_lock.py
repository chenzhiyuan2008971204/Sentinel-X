"""Execution lock for new downloads: a program cannot be started until it has been checked.

When a new program file appears in the Downloads folder, Sentinel X adds one access-control
entry to that file: "deny execute" for Everyone (SID S-1-1-0). Windows then refuses to start
it ("access denied") while reading it, copying it and scanning it still work. After the
scan the entry is removed again, unless the file was judged a threat or suspicious; then it
stays locked until the user unlocks it on the Real-time protection page.

Limits (also in the user manual): only image files that Windows starts or loads directly
(.exe, .com, .scr, .cpl, .dll, .pif) are locked; installers run by another program
(.msi by msiexec, scripts by their interpreter) are not. A copy of a locked file is not
locked. A program started in the moment between the download finishing and the lock is
not stopped. The file owner (the user) can always change the file's permissions.

Locked paths are kept in `exec_locks.json` in the data folder, so files locked when the app
stopped unexpectedly are checked again at the next start.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger(__name__)

LOCK_SUFFIXES = frozenset({".exe", ".com", ".scr", ".cpl", ".dll", ".pif"})
EVERYONE = "*S-1-1-0"
CREATE_NO_WINDOW = 0x08000000
PENDING = "pending"  # locked, waiting for the scan
HELD = "held"  # threat or suspicious: stays locked until the user unlocks it


def _icacls() -> str:
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe")


def _run(args: list[str]) -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run([_icacls(), *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def is_link(path: Path) -> bool:
    """Symbolic link, junction or other reparse point: icacls would change the file it points to."""
    try:
        st = os.lstat(path)
    except OSError:
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x400) or os.path.islink(path)  # FILE_ATTRIBUTE_REPARSE_POINT


def deny_execute(path: Path) -> bool:
    """Add "deny execute for Everyone" to the file. False if it could not be set (e.g. still in
    use) or if the path is a link (audit 8, L1: the lock must never land on another file)."""
    if is_link(path):
        return False
    return _run([str(path), "/deny", f"{EVERYONE}:(X)", "/Q"])


def allow_execute(path: Path) -> bool:
    """Remove the deny entries for Everyone that `deny_execute` added."""
    return _run([str(path), "/remove:d", EVERYONE, "/Q"])


def can_execute(path: Path) -> bool:
    """Whether the current user may open the file for execution (FILE_EXECUTE)."""
    if sys.platform != "win32":
        return True
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    h = k32.CreateFileW(str(path), 0x20, 0x7, None, 3, 0x80, None)  # FILE_EXECUTE, share all, OPEN_EXISTING
    if h in (None, wintypes.HANDLE(-1).value):
        return False
    k32.CloseHandle(h)
    return True


def lockable(path: str | Path) -> bool:
    return Path(path).suffix.lower() in LOCK_SUFFIXES


@dataclass
class LockEntry:
    path: str
    state: str  # PENDING or HELD
    reason: str = ""
    at: str = ""


class LockRegistry:
    """Paths Sentinel X locked, stored in a small JSON file (atomic replace)."""

    def __init__(self, file: Path) -> None:
        self._file = file
        self._lock = threading.Lock()
        self._entries: dict[str, LockEntry] = {}
        self._load()

    @staticmethod
    def key(path: str | Path) -> str:
        return os.path.normcase(os.path.abspath(str(path)))

    def _load(self) -> None:
        try:
            raw = json.loads(self._file.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                e = LockEntry(str(item["path"]), str(item["state"]), str(item.get("reason", "")), str(item.get("at", "")))
                if e.state in (PENDING, HELD):
                    self._entries[self.key(e.path)] = e
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError):
            log.warning("exec lock registry unreadable; starting empty", extra={"ctx": {"file": str(self._file)}})

    def _save(self) -> None:
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(e) for e in self._entries.values()], ensure_ascii=False, indent=1),
                       encoding="utf-8")
        os.replace(tmp, self._file)

    def get(self, path: str | Path) -> LockEntry | None:
        with self._lock:
            return self._entries.get(self.key(path))

    def put(self, entry: LockEntry) -> None:
        with self._lock:
            self._entries[self.key(entry.path)] = entry
            self._save()

    def remove(self, path: str | Path) -> None:
        with self._lock:
            if self._entries.pop(self.key(path), None) is not None:
                self._save()

    def entries(self, state: str | None = None) -> list[LockEntry]:
        with self._lock:
            return [e for e in self._entries.values() if state is None or e.state == state]
