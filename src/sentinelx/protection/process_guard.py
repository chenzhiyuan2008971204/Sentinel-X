"""Terminate processes started from a known threat (opt-in active response).

A process is terminated only when the SHA-256 of its executable exactly equals the hash of a
file Sentinel X has judged CONFIRMED_THREAT or holds in quarantine — for example a copy taken
out of the quarantine and run. Never terminated: critical Windows processes, programs with a
valid Microsoft signature (a "threat" verdict on those is treated as a false positive and only
reported), Sentinel X itself and its own child processes.

Limit: processes are found by polling (default every second), so a threat may run briefly
before it is stopped. Blocking it before it starts needs a kernel driver.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import psutil

log = logging.getLogger(__name__)

CRITICAL = frozenset({"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
                      "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "explorer.exe", "registry",
                      "memcompression", "msmpeng.exe", "securityhealthservice.exe"})
MAX_HASH_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class Termination:
    pid: int
    name: str
    path: str
    sha256: str
    killed: bool
    detail: str


def _sha256(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def microsoft_signed(path: str) -> bool:
    try:
        from sentinelx.core.enums import SignatureStatus
        from sentinelx.engines.authenticode import inspect_signature

        d = inspect_signature(Path(path))
        return d.status is SignatureStatus.VALID and bool(d.chain) and "Microsoft" in d.chain[0].subject
    except Exception:  # noqa: BLE001 - when unsure, do not treat as protected
        return False


class ProcessGuard:
    def __init__(self, threat_hashes: Callable[[], set[str]], on_event: Callable[[Termination], None], *,
                 interval_s: float = 1.0, protected: Callable[[str], bool] = microsoft_signed) -> None:
        self._hashes = threat_hashes
        self._on_event = on_event
        self._interval = interval_s
        self._protected = protected
        self._own = os.getpid()
        self._seen: set[tuple[int, float]] = set()
        self._last_threats: frozenset[str] = frozenset()
        self._cache: dict[tuple[str, int, int], str | None] = {}  # (path, size, mtime) -> sha256
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._seen = set()  # existing processes are checked too: a threat may already be running
        self._thread = threading.Thread(target=self._loop, name="sentinelx-process-guard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(10)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception:  # noqa: BLE001 - keep guarding
                log.exception("process guard cycle failed")
            self._stop.wait(self._interval)

    def _file_hash(self, path: str) -> str | None:
        try:
            st = os.stat(path)
        except OSError:
            return None
        key = (path.lower(), st.st_size, st.st_mtime_ns)
        if key not in self._cache:
            if len(self._cache) > 20_000:
                self._cache.clear()
            self._cache[key] = _sha256(path)
        return self._cache[key]

    def check_once(self) -> list[Termination]:
        threats = self._hashes()
        if frozenset(threats) != self._last_threats:
            # A new threat may already be running (e.g. a copy elsewhere): look at everything again.
            self._last_threats = frozenset(threats)
            self._seen = set()
        if not threats:
            return []  # nothing to look for; when a threat becomes known, every process is checked
        current: set[tuple[int, float]] = set()
        out = []
        # Only the process number and start time for every process (about 1 ms for 250 processes);
        # the program path is asked for new processes only. Asking it for all of them every second
        # cost about 180 ms of CPU per round (engineering audit 8, H1).
        for p in psutil.process_iter(["pid", "create_time"]):
            key = (p.info["pid"], p.info.get("create_time") or 0.0)
            current.add(key)
            if key in self._seen or p.info["pid"] in (0, 4, self._own):
                continue
            try:
                exe, ppid, name = p.exe(), p.ppid(), p.name()
            except (psutil.Error, OSError):
                continue  # ended meanwhile, or a protected system process
            if not exe or ppid == self._own:
                continue
            sha = self._file_hash(exe)
            if sha is None or sha not in threats:
                continue
            p.info["name"] = name
            out.append(self._terminate(p, exe, sha))
        self._seen = current
        return out

    def kill_path(self, path: str) -> list[Termination]:
        """Terminate running processes started from `path` (before quarantining it)."""
        out = []
        target = os.path.normcase(os.path.abspath(path))
        for p in psutil.process_iter(["pid", "name", "exe", "ppid"]):
            exe = p.info.get("exe")
            if exe and os.path.normcase(exe) == target and p.info["pid"] != self._own:
                out.append(self._terminate(p, exe, self._file_hash(exe) or ""))
        return out

    def _terminate(self, p: psutil.Process, exe: str, sha: str) -> Termination:
        name = (p.info.get("name") or Path(exe).name)
        if name.lower() in CRITICAL:
            ev = Termination(p.pid, name, exe, sha, False, "Windows 重要程序，不終止，只通知")
        elif self._protected(exe):
            ev = Termination(p.pid, name, exe, sha, False, "有效的微軟簽章，可能是誤判，不終止，只通知")
        else:
            try:
                p.kill()
                ev = Termination(p.pid, name, exe, sha, True, "已終止")
            except psutil.NoSuchProcess:
                ev = Termination(p.pid, name, exe, sha, False, "程序已自行結束")
            except psutil.AccessDenied:
                ev = Termination(p.pid, name, exe, sha, False, "權限不足，無法終止（可能需要系統管理員模式）")
        log.warning("threat process", extra={"ctx": {"pid": ev.pid, "path": exe, "killed": ev.killed}})
        self._on_event(ev)
        return ev
