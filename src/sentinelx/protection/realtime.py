"""Watch folders and drives; hand finished files to a scanner in small batches.

A file is scanned when it has not changed for `settle_s` seconds and can be opened for reading
(a download still being written is skipped until it is complete). Browser partial-download
names (.crdownload, .part, ...) are ignored; the final rename is caught as a move. Sentinel X's
own data folder is never watched. Files that stay locked are retried, then reported as not
assessed — never as clean.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelx.protection import fileid

log = logging.getLogger(__name__)

PARTIAL_SUFFIXES = frozenset({".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp"})
MAX_QUEUE = 20_000
MAX_BATCH = 50
MAX_ATTEMPTS = 20
RESCAN_AFTER_S = 300.0  # an unchanged file is not scanned again within this time


@dataclass
class _Pending:
    path: str
    last_event: float
    size: int = -1
    attempts: int = 0


class FolderScanner:
    def __init__(self, scan: Callable[[list[Path]], None], *, exclude: Sequence[Path], settle_s: float = 1.5,
                 on_locked: Callable[[Path], None] = lambda _p: None,
                 on_overflow: Callable[[int], None] = lambda _n: None,
                 on_seen: Callable[[str], None] = lambda _p: None,
                 skip: Callable[[str], bool] = lambda _p: False,
                 on_event: Callable[[str, str, str | None], None] = lambda _k, _s, _d: None,
                 first: Callable[[str], bool] = lambda _p: False) -> None:
        self._scan = scan
        self._on_event = on_event  # every raw event (kind, path, new path), e.g. for the ransomware detector
        self._first = first  # checked before everything else (programs locked until checked)
        self._skip = skip  # e.g. the whole-drive noise filter
        self._on_seen = on_seen  # called for every event (before settling), e.g. to lock a new program at once
        self._exclude = [os.path.normcase(str(p)).rstrip("\\/") for p in exclude]
        self._settle = settle_s
        self._on_locked = on_locked
        self._on_overflow = on_overflow
        self._pending: dict[str, _Pending] = {}
        # Windows can deliver a file's events after it was already scanned; an unchanged file is
        # not scanned (and reported) twice. path -> (size, (mtime_ns, change time), when scanned)
        self._recent: dict[str, tuple[int, tuple[int, int], float, str | None]] = {}
        self._lock = threading.Lock()
        self._dropped = 0
        self._observer = None
        self._watched: dict[str, object] = {}  # folder -> watch handle
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- folders ----
    def watched(self) -> list[str]:
        return sorted(self._watched)

    def watch(self, folder: Path) -> bool:
        key = os.path.normcase(str(folder))
        if key in self._watched or self._observer is None or not folder.is_dir():
            return False
        from watchdog.events import FileSystemEvent, FileSystemEventHandler

        scanner = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event: FileSystemEvent) -> None:
                if event.is_directory:
                    return
                if event.event_type in ("created", "modified", "moved", "deleted"):
                    try:
                        scanner._on_event(event.event_type, str(event.src_path), getattr(event, "dest_path", None) or None)
                    except Exception:  # noqa: BLE001 - an event handler must never stop the watcher
                        log.exception("on_event failed")
                if event.event_type not in ("created", "modified", "moved"):
                    return
                target = getattr(event, "dest_path", None) if event.event_type == "moved" else event.src_path
                if target:
                    scanner.notify(str(target), event.event_type)

        try:
            self._watched[key] = self._observer.schedule(Handler(), str(folder), recursive=True)  # type: ignore[attr-defined]
        except OSError:
            log.warning("cannot watch folder", extra={"ctx": {"folder": str(folder)}})
            return False
        return True

    def unwatch(self, folder: Path) -> None:
        key = os.path.normcase(str(folder))
        handle = self._watched.pop(key, None)
        if handle is not None and self._observer is not None:
            try:
                self._observer.unschedule(handle)  # type: ignore[attr-defined]
            except (KeyError, OSError):
                pass

    # ---- events ----
    def _excluded(self, path: str) -> bool:
        n = os.path.normcase(path)
        if Path(n).suffix in PARTIAL_SUFFIXES:
            return True
        if any(n == e or n.startswith(e + os.sep) for e in self._exclude):
            return True
        return self._skip(path)

    def notify(self, path: str, kind: str = "modified") -> None:
        if self._excluded(path):
            return
        try:
            self._on_seen(path, kind)
        except Exception:  # noqa: BLE001 - an event handler must never stop the watcher
            log.exception("on_seen failed")
        with self._lock:
            if path in self._pending:
                self._pending[path].last_event = time.monotonic()
            elif len(self._pending) >= MAX_QUEUE:
                self._dropped += 1
            else:
                self._pending[path] = _Pending(path, time.monotonic())

    def remember_content(self, path: str, sha256: str | None) -> None:
        """The scanned content's SHA-256 (from the scan result), for later change-time checks."""
        with self._lock:
            prev = self._recent.get(path)
            if prev is not None and sha256:
                self._recent[path] = (prev[0], prev[1], prev[2], sha256)

    def mark_checked(self, path: str) -> None:
        """Sentinel X itself just changed this file's permissions (execution lock): if the content
        is still the scanned one, the change event that follows is not a new version."""
        with self._lock:
            prev = self._recent.get(path)
        st = fileid.stamp(path)
        if prev is None or prev[3] is None or st is None or fileid.sha256(path) != prev[3]:
            return
        with self._lock:
            self._recent[path] = (st[0], st[1:], prev[2], prev[3])

    def queue_length(self) -> int:
        with self._lock:
            return len(self._pending)

    # ---- lifecycle ----
    def start(self) -> None:
        if self._thread is not None:
            return
        from watchdog.observers import Observer

        self._observer = Observer()
        self._observer.start()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sentinelx-realtime", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(30)
            self._thread = None
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(5)
            self._observer = None
        self._watched.clear()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                n = self.process_ready()
            except Exception:  # noqa: BLE001 - keep protecting
                log.exception("real-time scan cycle failed")
                n = 0
            # A full batch means more files are waiting: continue at once (audit 8, M3; the pause
            # limited real-time checks to 100 files a second even with an instant scanner).
            if n < MAX_BATCH:
                self._stop.wait(0.5)

    def process_ready(self, now: float | None = None) -> int:
        """Scan files that are settled and readable. Returns how many were sent to the scanner.

        File checks (exists, size, readable) happen outside the lock, so the watcher thread is
        never kept waiting and Windows' event buffer does not fill up meanwhile (audit 8, M3)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            dropped, self._dropped = self._dropped, 0
            settled = [(path, p, p.last_event) for path, p in self._pending.items() if now - p.last_event >= self._settle]
        # Locked programs first: the user cannot open them until they are checked, and a backlog
        # of other files (an unpacked archive, a build) must not keep them waiting.
        settled.sort(key=lambda s: not self._first(s[0]))
        ready: list[Path] = []
        for path, p, seen_at in settled:
            if len(ready) >= MAX_BATCH:
                break
            gone = not os.path.isfile(path)
            size = mtime = None
            failed = False
            same_content = False
            if not gone:
                try:
                    size = os.path.getsize(path)
                    with open(path, "rb"):
                        pass
                    st = fileid.stamp(path)  # with Windows' change time (audit 8, L2)
                    if st is None:
                        raise OSError("gone")
                    mtime = st[1:]
                    with self._lock:
                        prev = self._recent.get(path)
                    if (prev is not None and prev[3] and prev[0] == size and prev[1][0] == mtime[0]
                            and prev[1] != mtime and now - prev[2] < RESCAN_AFTER_S):
                        # Only the change time moved: same content? (audit 8, L2; hashed outside the lock)
                        same_content = fileid.sha256(path) == prev[3]
                except OSError:
                    failed = True
            with self._lock:
                if self._pending.get(path) is not p:
                    continue  # handled meanwhile
                newer = p.last_event != seen_at  # another event arrived during the check
                if newer and (gone or failed):
                    continue  # let it settle again
                if newer and size != p.size:
                    p.size = size  # remember what was seen; the newer event's time decides when to look again
                    continue
                if gone:
                    del self._pending[path]  # deleted or renamed meanwhile
                    continue
                if failed:
                    p.attempts += 1
                    p.last_event = now
                    if p.attempts >= MAX_ATTEMPTS:
                        del self._pending[path]
                        locked_out = True
                    else:
                        locked_out = False
                elif size != p.size:  # still growing: wait one more settle period
                    p.size, p.last_event = size, now
                    continue
                else:
                    del self._pending[path]
                    if newer:  # scan what was seen now; the newer change gets its own turn
                        self._pending[path] = _Pending(path, p.last_event)
                    locked_out = False
                    prev = self._recent.get(path)
                    if prev is not None and now - prev[2] < RESCAN_AFTER_S and (prev[:2] == (size, mtime) or same_content):
                        self._recent[path] = (size, mtime, prev[2], prev[3])  # type: ignore[arg-type]
                        continue  # same content seen moments ago: a late duplicate event
                    if len(self._recent) > MAX_QUEUE:
                        self._recent.clear()
                    self._recent[path] = (size, mtime, now, None)  # type: ignore[arg-type]
                    ready.append(Path(path))
                    continue
            if locked_out:
                self._on_locked(Path(path))
        if dropped:
            self._on_overflow(dropped)
        if ready:
            self._scan(ready)
        return len(ready)

class VaultWatch:
    """Alert when the quarantine vault folder changes and Sentinel X did not change it."""

    def __init__(self, vault_dir: Path, own_change_age: Callable[[], float],
                 on_tamper: Callable[[str, str], None], *, grace_s: float = 5.0) -> None:
        self._dir = vault_dir
        self._age = own_change_age
        self._on_tamper = on_tamper
        self._grace = grace_s
        self._observer = None
        self._last_alert: dict[str, float] = {}  # one alert per file per 10 s (created+modified+...)

    def report(self, kind: str, path: str) -> None:
        if self._age() <= self._grace:
            return  # Sentinel X itself is changing the vault
        now = time.monotonic()
        if now - self._last_alert.get(path, -1e9) < 10.0:
            return
        self._last_alert[path] = now
        self._on_tamper(kind, path)

    def start(self) -> None:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers import Observer

        guard = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event: FileSystemEvent) -> None:
                if event.event_type in ("opened", "closed", "closed_no_write"):
                    return
                guard.report(event.event_type, str(getattr(event, "dest_path", "") or event.src_path))

        if not self._dir.is_dir():
            return
        self._observer = Observer()
        self._observer.schedule(Handler(), str(self._dir), recursive=True)
        self._observer.start()

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(5)
            self._observer = None
