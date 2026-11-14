"""Background loop: poll collectors -> store events -> correlate -> store alerts.

Runs on a plain thread (no Qt). The GUI reads results from the database. `stop()` returns
after the current cycle finishes; every collector call is bounded (event log reads use a
1 s wait, psutil calls are synchronous snapshots).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from sentinelx.monitor.collectors import Collector, CollectorStatus
from sentinelx.monitor.correlation import Correlator, ThreatIndex
from sentinelx.storage.event_repository import EventRepository

log = logging.getLogger(__name__)


@dataclass
class RunnerStats:
    cycles: int = 0
    events: int = 0
    alerts: int = 0
    last_error: str | None = None
    active: list[str] = field(default_factory=list)


class MonitorRunner:
    PRUNE_EVERY = 100

    def __init__(self, collectors: list[Collector], repo: EventRepository, correlator: Correlator,
                 threat_index: Callable[[], ThreatIndex], *, interval_s: float = 3.0, retention: int = 200_000) -> None:
        self._collectors = collectors
        self._repo = repo
        self._correlator = correlator
        self._index = threat_index
        self._interval = interval_s
        self._retention = retention
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active: list[Collector] = []
        self.stats = RunnerStats()
        self.statuses: list[CollectorStatus] = []

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> list[CollectorStatus]:
        if self.running:
            return self.statuses
        self._stop.clear()
        self.stats = RunnerStats()
        self.statuses, self._active = [], []
        for c in self._collectors:
            st = c.status()
            if st.available:
                try:
                    c.start()
                    self._active.append(c)
                except Exception as exc:  # noqa: BLE001 - one broken source must not stop the others
                    log.exception("collector start failed", extra={"ctx": {"collector": c.name}})
                    st = CollectorStatus(st.name, st.source, False, f"啟動失敗：{exc}", st.requires_admin)
            self.statuses.append(st)
        self.stats.active = [c.name for c in self._active]
        self._thread = threading.Thread(target=self._loop, name="sentinelx-monitor", daemon=True)
        self._thread.start()
        return self.statuses

    def run_once(self) -> int:
        """One poll/store/correlate cycle (also used directly by tests). Returns new event count."""
        batch = []
        for c in self._active:
            try:
                batch.extend(c.poll())
            except Exception as exc:  # noqa: BLE001 - keep other sources running, report the error
                self.stats.last_error = f"{c.name}：{type(exc).__name__}: {exc}"
                log.exception("collector poll failed", extra={"ctx": {"collector": c.name}})
        stored = self._repo.insert(batch)
        if stored:
            for a in self._correlator.process(stored, self._index()):
                _, created = self._repo.add_alert(a)
                self.stats.alerts += int(created)
        self.stats.cycles += 1
        self.stats.events += len(stored)
        if self.stats.cycles % self.PRUNE_EVERY == 0:
            self._repo.prune(self._retention)
        return len(stored)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # noqa: BLE001 - logged and shown; the loop keeps going
                self.stats.last_error = f"{type(exc).__name__}: {exc}"
                log.exception("monitor cycle failed")
            self._stop.wait(self._interval)

    def stop(self, timeout: float = 15.0) -> bool:
        """Stop the loop and the collectors. Returns False if the loop did not finish within
        `timeout`: then the collectors are left alone (the loop may still be using them) and
        the runner still counts as running, so it cannot be started a second time."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                log.error("monitor loop did not stop in time", extra={"ctx": {"timeout_s": timeout}})
                return False
            self._thread = None
        for c in self._active:
            try:
                c.stop()
            except Exception:  # noqa: BLE001
                log.exception("collector stop failed", extra={"ctx": {"collector": c.name}})
        self._active = []
        return True
