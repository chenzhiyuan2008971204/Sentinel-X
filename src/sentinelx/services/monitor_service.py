"""Behaviour Monitor use cases: sources, start/stop, timeline, alerts, watched folders,
admin relaunch request and the Sysmon setup guide."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path

from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.app.paths import AppPaths
from sentinelx.core.enums import AlertStatus, AuditActor, EventSource, PrivilegeLevel
from sentinelx.monitor.collectors import (
    Collector,
    CollectorStatus,
    FolderWatchCollector,
    NetworkCollector,
    ProcessCollector,
    defender_collector,
    security_log_collector,
    sysmon_collector,
)
from sentinelx.monitor.correlation import Correlator, ThreatIndex, ThreatInfo
from sentinelx.monitor.events import EventKind, StoredEvent
from sentinelx.monitor.runner import MonitorRunner, RunnerStats
from sentinelx.scanner.exclusions import norm_path
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.event_repository import AlertRow, EventRepository
from sentinelx.storage.verdict_repository import VerdictRepository

SYSMON_URL = "https://learn.microsoft.com/sysinternals/downloads/sysmon"
SYSMON_CONFIG = Path(__file__).resolve().parent.parent / "resources" / "sysmon-sentinelx.xml"
SYSMON_STEPS = (
    "1. 從微軟官方網站下載 Sysmon（Sysinternals）。Sentinel X 不會替你下載或安裝。\n"
    "2. 儲存下方的建議設定檔，並先閱讀內容。\n"
    "3. 以「系統管理員」開啟終端機，在 Sysmon 解壓縮的資料夾執行：\n"
    "   Sysmon64.exe -accepteula -i sysmon-sentinelx.xml\n"
    "4. 安裝後 Sysmon 會以系統服務與驅動程式執行；要移除時執行 Sysmon64.exe -u。\n"
    "5. 讀取 Sysmon 日誌需要系統管理員權限：在 Sentinel X 按「以系統管理員身分重新啟動」。"
)


class MonitorService:
    def __init__(self, paths: AppPaths, config: AppConfig, store: ConfigStore, events: EventRepository,
                 verdicts: VerdictRepository, audit: AuditLog, privilege: PrivilegeLevel,
                 *, collector_factory: Callable[[AppConfig], list[Collector]] | None = None,
                 relauncher: Callable[[], bool] | None = None) -> None:
        self._paths = paths
        self._config = config
        self._store = store
        self._events = events
        self._verdicts = verdicts
        self._audit = audit
        self.privilege = privilege
        self._factory = collector_factory or self._default_collectors
        self._relauncher = relauncher
        self._runner: MonitorRunner | None = None

    # ---------- sources ----------
    def _default_collectors(self, cfg: AppConfig) -> list[Collector]:
        m = cfg.monitor
        out: list[Collector] = []
        if m.processes:
            out.append(ProcessCollector(interval_s=m.poll_interval_s))
        if m.network:
            out.append(NetworkCollector())
        if m.folders:
            out.append(FolderWatchCollector([Path(d) for d in m.watch_dirs], exclude=[self._paths.root]))
        if m.sysmon:
            out.append(sysmon_collector())
        if m.security_log:
            out.append(security_log_collector())
        if m.defender_log:
            out.append(defender_collector())
        return out

    def statuses(self) -> list[CollectorStatus]:
        if self._runner is not None and self._runner.running:
            return list(self._runner.statuses)
        return [c.status() for c in self._factory(self._config)]

    # ---------- run ----------
    @property
    def running(self) -> bool:
        return self._runner is not None and self._runner.running

    @property
    def stats(self) -> RunnerStats | None:
        return self._runner.stats if self._runner else None

    def threat_index(self) -> ThreatIndex:
        idx = ThreatIndex()
        for path, sha, cls, vid, quarantined in self._verdicts.threat_index_rows():
            info = ThreatInfo(cls, vid, quarantined)
            idx.by_path[norm_path(path)] = info
            if sha:
                idx.by_sha[sha] = info
        return idx

    def start(self) -> list[CollectorStatus]:
        if self.running:
            assert self._runner is not None
            return self._runner.statuses
        m = self._config.monitor
        self._runner = MonitorRunner(self._factory(self._config), self._events, Correlator(), self.threat_index,
                                     interval_s=m.poll_interval_s, retention=m.retention_events)
        statuses = self._runner.start()
        self._audit.record("MONITOR_START", actor=AuditActor.USER,
                           detail={"active": [s.name for s in statuses if s.available],
                                   "unavailable": {s.name: s.detail for s in statuses if not s.available}})
        return statuses

    def stop(self) -> None:
        if self._runner is None:
            return
        was_running = self._runner.running
        stats = self._runner.stats
        self._runner.stop()
        if was_running:
            self._audit.record("MONITOR_STOP", actor=AuditActor.USER,
                               detail={"events": stats.events, "alerts": stats.alerts})

    def run_once(self) -> int:
        """Tests / manual refresh: one cycle without waiting for the timer."""
        return self._runner.run_once() if self._runner else 0

    # ---------- data ----------
    def events(self, *, source: EventSource | None = None, kind: EventKind | None = None, text: str | None = None,
               limit: int = 500) -> list[StoredEvent]:
        return self._events.query(source=source, kind=kind, text=(text or "").strip() or None, limit=limit)

    def alerts(self, include_closed: bool = False) -> list[AlertRow]:
        return self._events.alerts(include_closed)

    def alert_events(self, alert: AlertRow) -> list[StoredEvent]:
        return self._events.events_by_ids(alert.event_ids)

    def set_alert_status(self, alert_id: int, status: AlertStatus) -> AlertRow | None:
        row = self._events.set_alert_status(alert_id, status)
        if row is not None:
            self._audit.record(f"ALERT_{status.value}", actor=AuditActor.USER, subject=row.title,
                               detail={"alert_id": alert_id})
        return row

    def open_alert_count(self) -> int:
        return self._events.open_alert_count()

    # ---------- watched folders ----------
    @property
    def watch_dirs(self) -> list[str]:
        return list(self._config.monitor.watch_dirs)

    def add_watch_dir(self, folder: Path) -> None:
        p = Path(os.path.abspath(folder))
        if not p.is_dir():
            raise ValueError("資料夾不存在。")
        if norm_path(p) == norm_path(self._paths.root) or self._paths.root in p.parents:
            raise ValueError("不能監看 Sentinel X 自己的資料夾。")
        if any(norm_path(d) == norm_path(p) for d in self._config.monitor.watch_dirs):
            raise ValueError("這個資料夾已在監看清單中。")
        self._config.monitor.watch_dirs.append(str(p))
        self._store.save(self._config)
        self._audit.record("MONITOR_WATCH_ADD", actor=AuditActor.USER, subject=str(p))

    def remove_watch_dir(self, folder: str) -> None:
        before = list(self._config.monitor.watch_dirs)
        self._config.monitor.watch_dirs = [d for d in before if norm_path(d) != norm_path(folder)]
        if self._config.monitor.watch_dirs != before:
            self._store.save(self._config)
            self._audit.record("MONITOR_WATCH_REMOVE", actor=AuditActor.USER, subject=folder)

    # ---------- elevation / Sysmon ----------
    def request_elevation(self) -> bool:
        """Ask Windows for an elevated relaunch (UAC). True = accepted; the caller then quits."""
        if self._relauncher is None:
            from sentinelx.app.privilege import relaunch_elevated

            self._relauncher = relaunch_elevated
        ok = self._relauncher()
        self._audit.record("ELEVATION_REQUESTED", actor=AuditActor.USER, detail={"accepted": ok})
        return ok

    def sysmon_installed(self) -> bool:
        sysmon = next((s for s in self.statuses() if s.source is EventSource.SYSMON), None)
        return sysmon is not None and (sysmon.available or sysmon.requires_admin)

    @staticmethod
    def sysmon_steps() -> str:
        return SYSMON_STEPS

    def save_sysmon_config(self, dest: Path) -> Path:
        if dest.exists():
            raise ValueError("目標檔案已存在，請選擇其他名稱。")
        shutil.copyfile(SYSMON_CONFIG, dest)
        self._audit.record("SYSMON_CONFIG_SAVED", actor=AuditActor.USER, subject=str(dest))
        return dest
