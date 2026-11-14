"""Run ClamAV's resident scanner (clamd) for real-time protection.

clamscan reloads all signatures on every start (10–20 s), too slow for scanning each new file.
clamd loads them once (about 1 GB of memory) and then answers in about a second.

- Listens on 127.0.0.1 only, on a free port chosen at start; the configuration is written by
  Sentinel X with fixed content (UTF-8, so a Chinese user name in the path works).
- The process is put in a Windows job object that is closed when Sentinel X exits, so clamd
  never outlives the app, even after a crash.
- Files are sent by content (INSTREAM): clamd never opens the user's files itself.
"""

from __future__ import annotations

import ctypes
import logging
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

from sentinelx.engines.clamd import ClamdEngine

log = logging.getLogger(__name__)
CREATE_NO_WINDOW = 0x08000000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _BASIC(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class _EXTENDED(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC), ("IoInfo", ctypes.c_uint64 * 6),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def kill_with_parent(proc: subprocess.Popen) -> int | None:  # type: ignore[type-arg]
    """Job object with KILL_ON_JOB_CLOSE: the child dies when this process's handle closes."""
    if sys.platform != "win32":
        return None
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = _EXTENDED()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    k32.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info))
    if not k32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))):  # type: ignore[attr-defined]
        log.warning("could not tie clamd to the app", extra={"ctx": {"error": ctypes.get_last_error()}})
    return int(job)


class ClamdManager:
    STOPPED, STARTING, READY, ERROR = "stopped", "starting", "ready", "error"

    def __init__(self, clamd_exe: Path | None, database_dir: Path, work_dir: Path, *, max_file_mb: int = 100,
                 launcher: list[str] | None = None, ready_timeout_s: float = 300.0,
                 on_state: Callable[[str, str], None] = lambda _s, _d: None) -> None:
        """`launcher` replaces the clamd.exe invocation (tests use a fake clamd)."""
        self._exe = clamd_exe
        self._db = database_dir
        self._work = work_dir
        self._max_mb = max_file_mb
        self._launcher = launcher
        self._ready_timeout = ready_timeout_s
        self._on_state = on_state
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]
        self._job: int | None = None
        self._log_file = None
        self.port = 0
        self.state = self.STOPPED
        self.detail = ""
        self._lock = threading.Lock()

    def _set(self, state: str, detail: str = "") -> None:
        self.state, self.detail = state, detail
        self._on_state(state, detail)

    def config_text(self) -> str:
        mb = f"{self._max_mb}M"
        return (f"TCPSocket {self.port}\nTCPAddr 127.0.0.1\nDatabaseDirectory {self._db}\n"
                f"TemporaryDirectory {self._work / 'tmp'}\nStreamMaxLength {mb}\nMaxFileSize {mb}\n"
                f"MaxScanSize {mb}\nForeground yes\nLogFile {self._work / 'clamd.log'}\nLogFileMaxSize 2M\n"
                f"LogTime yes\nConcurrentDatabaseReload no\n")

    def start(self) -> None:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return
            if self._launcher is None and (self._exe is None or not self._exe.is_file()):
                self._set(self.ERROR, "找不到 clamd.exe（ClamAV 未安裝或不完整）。")
                return
            if self._launcher is None and not self._db.is_dir():
                self._set(self.ERROR, "尚未下載病毒碼，請先在「設定 → ClamAV 病毒碼」更新。")
                return
            (self._work / "tmp").mkdir(parents=True, exist_ok=True)
            self.port = free_port()
            conf = self._work / "clamd.conf"
            conf.write_text(self.config_text(), encoding="utf-8")
            cmd = [*(self._launcher or [str(self._exe)]), f"--config-file={conf}"]
            self._log_file = open(self._work / "clamd.out.log", "wb")  # noqa: SIM115 - closed in stop()
            self._proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=self._log_file,
                                          stderr=subprocess.STDOUT,
                                          creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            self._job = kill_with_parent(self._proc)
            self._set(self.STARTING, "載入病毒碼中（第一次約需 20–60 秒）…")
            threading.Thread(target=self._wait_ready, args=(self._proc,), name="sentinelx-clamd-wait",
                             daemon=True).start()

    def _wait_ready(self, proc: subprocess.Popen) -> None:  # type: ignore[type-arg]
        started = time.monotonic()
        while time.monotonic() - started < self._ready_timeout:
            if proc.poll() is not None:
                self._set(self.ERROR, f"clamd 結束了（代碼 {proc.returncode}），詳見 {self._work / 'clamd.log'}")
                return
            st = ClamdEngine("127.0.0.1", self.port, timeout_s=5).availability(refresh=True)
            if st.available:
                self._set(self.READY, f"ClamAV {st.version}，病毒碼 {st.rules_version}，127.0.0.1:{self.port}")
                return
            time.sleep(1.0)
        self._set(self.ERROR, "clamd 在時限內沒有完成載入。")

    def engine(self, timeout_s: int = 120) -> ClamdEngine | None:
        return ClamdEngine("127.0.0.1", self.port, timeout_s=timeout_s) if self.state == self.READY else None

    def stop(self) -> None:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                self._proc.kill()
                try:
                    self._proc.wait(10)
                except subprocess.TimeoutExpired:
                    pass
            self._proc = None
            if self._job:
                ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(self._job))
                self._job = None
            if self._log_file is not None:
                self._log_file.close()
                self._log_file = None
            self._set(self.STOPPED, "")
