"""Telemetry collectors. All are read-only observers.

- ProcessCollector / NetworkCollector (psutil): polling snapshots. Short-lived processes and
  connections that start and end between two polls are not seen; this is stated in the UI.
- FolderWatchCollector (watchdog / ReadDirectoryChangesW): user-selected folders only.
- EventLogCollector: Windows event channels through wevtapi (Sysmon, Security 4688,
  Defender detections). Unavailable channels report why (not installed / needs admin).

Sentinel X's own child processes (e.g. clamscan) are ignored by default so the monitor does
not report itself.
"""

from __future__ import annotations

import logging
import os
import threading
import xml.etree.ElementTree as ET
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import psutil

from sentinelx.core.enums import EventSource
from sentinelx.monitor import wevt
from sentinelx.monitor.events import EventKind, SecurityEventIn
from sentinelx.scanner.exclusions import norm_path

log = logging.getLogger(__name__)
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class CollectorStatus:
    name: str
    source: EventSource
    available: bool
    detail: str
    requires_admin: bool = False


class Collector(Protocol):
    name: str
    source: EventSource

    def status(self) -> CollectorStatus: ...
    def start(self) -> None: ...
    def poll(self) -> list[SecurityEventIn]: ...
    def stop(self) -> None: ...


# ---------------------------------------------------------------- psutil
class ProcessCollector:
    name = "程序（psutil）"
    source = EventSource.PSUTIL

    def __init__(self, *, ignore_self: bool = True, interval_s: float = 3.0) -> None:
        self._ignore_self = ignore_self
        self._interval = interval_s
        self._seen: set[tuple[int, float]] = set()
        self._own = os.getpid()

    def status(self) -> CollectorStatus:
        return CollectorStatus(self.name, self.source, True,
                               f"每 {self._interval:g} 秒輪詢一次，存在時間很短的程序可能觀察不到；"
                               "一般權限下部分系統程序的路徑與命令列無法讀取。")

    def _snapshot(self) -> dict[tuple[int, float], psutil.Process]:
        out = {}
        for p in psutil.process_iter(["pid", "create_time"]):
            ct = p.info.get("create_time")
            if ct is not None:
                out[(p.info["pid"], ct)] = p
        return out

    def start(self) -> None:
        self._seen = set(self._snapshot())

    def poll(self) -> list[SecurityEventIn]:
        snap = self._snapshot()
        new = [k for k in snap if k not in self._seen]
        self._seen = set(snap)
        events = []
        for key in sorted(new, key=lambda k: k[1]):
            p = snap[key]
            try:
                with p.oneshot():
                    ppid = p.ppid()
                    if self._ignore_self and (p.pid == self._own or ppid == self._own):
                        continue
                    exe = cmd = name = None
                    denied = []
                    try:
                        name = p.name()
                    except psutil.AccessDenied:
                        denied.append("name")
                    try:
                        exe = p.exe() or None
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        denied.append("exe")
                    try:
                        cmd = " ".join(p.cmdline()) or None
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        denied.append("cmdline")
                    parent = None
                    try:
                        parent = psutil.Process(ppid).name() if ppid else None
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except psutil.NoSuchProcess:
                continue  # exited before we could read it
            except psutil.AccessDenied:
                continue  # parent id unreadable: skip this process only, never the whole poll
            events.append(SecurityEventIn(
                self.source, EventKind.PROCESS_CREATE, _iso(key[1]), name, exe, p.pid, ppid, cmd,
                details={"observed_by": "polling", "parent_name": parent, "access_denied": denied},
            ))
        return events

    def stop(self) -> None:
        self._seen.clear()


class NetworkCollector:
    name = "網路連線（psutil）"
    source = EventSource.PSUTIL

    def __init__(self, *, ignore_self: bool = True) -> None:
        self._ignore_self = ignore_self
        self._seen: set[tuple] = set()  # type: ignore[type-arg]
        self._own = os.getpid()

    def status(self) -> CollectorStatus:
        try:
            psutil.net_connections("inet")
        except psutil.AccessDenied:
            return CollectorStatus(self.name, self.source, False, "需要系統管理員權限才能列出連線。", True)
        return CollectorStatus(self.name, self.source, True,
                               "以輪詢方式記錄新的對外連線（含遠端位址與埠）；很短暫的連線可能觀察不到。")

    @staticmethod
    def _key(c) -> tuple | None:  # type: ignore[no-untyped-def,type-arg]
        if not c.raddr or not c.pid:
            return None
        return (c.pid, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.type)

    def start(self) -> None:
        self._seen = {k for c in psutil.net_connections("inet") if (k := self._key(c))}

    def poll(self) -> list[SecurityEventIn]:
        conns = psutil.net_connections("inet")
        current = {}
        for c in conns:
            k = self._key(c)
            if k:
                current[k] = c
        events = []
        now = _now()
        names: dict[int, tuple[str | None, str | None]] = {}
        for k, c in current.items():
            if k in self._seen or (self._ignore_self and c.pid == self._own):
                continue
            if c.pid not in names:
                try:
                    pr = psutil.Process(c.pid)
                    exe = None
                    try:
                        exe = pr.exe() or None
                    except psutil.AccessDenied:
                        pass
                    names[c.pid] = (pr.name(), exe)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    names[c.pid] = (None, None)
            pname, pexe = names[c.pid]
            events.append(SecurityEventIn(
                self.source, EventKind.NET_CONNECT, now, pname, pexe, c.pid, None, None, None,
                c.raddr.ip, c.raddr.port,
                details={"local": f"{c.laddr.ip}:{c.laddr.port}", "status": c.status,
                         "protocol": "TCP" if c.type == 1 else "UDP", "observed_by": "polling"},
            ))
        self._seen = set(current)
        return events

    def stop(self) -> None:
        self._seen.clear()


# ---------------------------------------------------------------- folder watch
class FolderWatchCollector:
    name = "資料夾監看"
    source = EventSource.FSWATCH
    MAX_QUEUE = 50_000

    def __init__(self, folders: list[Path], exclude: list[Path] | None = None) -> None:
        self._folders = [Path(f) for f in folders]
        self._exclude = [norm_path(p) for p in (exclude or [])]
        self._queue: deque[tuple[EventKind, str, str | None, str]] = deque(maxlen=self.MAX_QUEUE)
        self._dropped = 0
        self._lock = threading.Lock()
        self._observer = None

    def status(self) -> CollectorStatus:
        if not self._folders:
            return CollectorStatus(self.name, self.source, False, "尚未設定要監看的資料夾。")
        missing = [str(f) for f in self._folders if not f.is_dir()]
        if missing:
            return CollectorStatus(self.name, self.source, False, f"資料夾不存在：{'、'.join(missing)}")
        return CollectorStatus(self.name, self.source, True, "監看：" + "、".join(str(f) for f in self._folders))

    def _excluded(self, path: str) -> bool:
        n = norm_path(path)
        return any(n == e or n.startswith(e + os.sep) for e in self._exclude)

    def _push(self, kind: EventKind, path: str, dest: str | None) -> None:
        if self._excluded(path):
            return
        with self._lock:
            if len(self._queue) == self.MAX_QUEUE:
                self._dropped += 1
            self._queue.append((kind, path, dest, _now()))

    def start(self) -> None:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers import Observer

        collector = self
        mapping = {"created": EventKind.FILE_CREATE, "modified": EventKind.FILE_MODIFY,
                   "deleted": EventKind.FILE_DELETE, "moved": EventKind.FILE_MOVE}

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event: FileSystemEvent) -> None:
                if event.is_directory or event.event_type not in mapping:
                    return
                dest = getattr(event, "dest_path", None) or None
                collector._push(mapping[event.event_type], str(event.src_path), str(dest) if dest else None)

        obs = Observer()
        for f in self._folders:
            if f.is_dir():
                obs.schedule(Handler(), str(f), recursive=True)
        obs.start()
        self._observer = obs

    def poll(self) -> list[SecurityEventIn]:
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
            dropped, self._dropped = self._dropped, 0
        seen: set[tuple[EventKind, str, str | None]] = set()
        events = []
        for kind, path, dest, at in items:  # coalesce repeated events within one poll
            if (kind, path, dest) in seen:
                continue
            seen.add((kind, path, dest))
            target = dest if kind is EventKind.FILE_MOVE and dest else path
            details = {"from": path} if kind is EventKind.FILE_MOVE else {}
            events.append(SecurityEventIn(self.source, kind, at, target_path=target, details=details))
        if dropped:
            log.warning("file events dropped", extra={"ctx": {"dropped": dropped}})
            events.append(SecurityEventIn(self.source, EventKind.FILE_MODIFY, _now(),
                                          details={"overflow_dropped": dropped,
                                                   "note": "事件過多，部分檔案事件未記錄"}))
        return events

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(5)
            self._observer = None


# ---------------------------------------------------------------- event logs
@dataclass(frozen=True)
class ParsedEvent:
    record_id: int
    event_id: int
    time: str
    data: dict[str, str]


def parse_event_xml(xml: str) -> ParsedEvent:
    root = ET.fromstring(xml)
    sys_el = root.find("e:System", _NS)
    if sys_el is None:
        raise ValueError("no System element")
    rid = int(sys_el.findtext("e:EventRecordID", "0", _NS))
    eid = int(sys_el.findtext("e:EventID", "0", _NS))
    tc = sys_el.find("e:TimeCreated", _NS)
    raw_t = tc.get("SystemTime", "") if tc is not None else ""
    t = raw_t[:19] + "Z" if len(raw_t) >= 19 else _now()
    data: dict[str, str] = {}
    ed = root.find("e:EventData", _NS)
    if ed is not None:
        for d in ed.findall("e:Data", _NS):
            name = d.get("Name")
            if name:
                data[name] = d.text or ""
    return ParsedEvent(rid, eid, t, data)


def _int(v: str | None, base: int = 10) -> int | None:
    if not v:
        return None
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v, base)
    except ValueError:
        return None


def _sha_from_hashes(h: str | None) -> str | None:
    for part in (h or "").split(","):
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].lower()
    return None


def sysmon_event(p: ParsedEvent) -> SecurityEventIn | None:
    d = p.data
    ref = f"Sysmon:{p.record_id}"
    image = d.get("Image") or None
    name = Path(image).name if image else None
    if p.event_id == 1:
        return SecurityEventIn(EventSource.SYSMON, EventKind.PROCESS_CREATE, p.time, name, image,
                               _int(d.get("ProcessId")), _int(d.get("ParentProcessId")), d.get("CommandLine") or None,
                               sha256=_sha_from_hashes(d.get("Hashes")), raw_ref=ref,
                               details={"parent_image": d.get("ParentImage"), "user": d.get("User"),
                                        "parent_name": Path(d["ParentImage"]).name if d.get("ParentImage") else None})
    if p.event_id == 3:
        return SecurityEventIn(EventSource.SYSMON, EventKind.NET_CONNECT, p.time, name, image,
                               _int(d.get("ProcessId")), None, None, None, d.get("DestinationIp") or None,
                               _int(d.get("DestinationPort")), raw_ref=ref,
                               details={"protocol": d.get("Protocol"), "initiated": d.get("Initiated"),
                                        "destination_host": d.get("DestinationHostname")})
    if p.event_id == 11:
        return SecurityEventIn(EventSource.SYSMON, EventKind.FILE_CREATE, p.time, name, image,
                               _int(d.get("ProcessId")), target_path=d.get("TargetFilename") or None, raw_ref=ref)
    if p.event_id in (23, 26):
        return SecurityEventIn(EventSource.SYSMON, EventKind.FILE_DELETE, p.time, name, image,
                               _int(d.get("ProcessId")), target_path=d.get("TargetFilename") or None,
                               sha256=_sha_from_hashes(d.get("Hashes")), raw_ref=ref)
    return None


def security_event(p: ParsedEvent) -> SecurityEventIn | None:
    if p.event_id != 4688:
        return None
    d = p.data
    image = d.get("NewProcessName") or None
    parent = d.get("ParentProcessName") or None
    return SecurityEventIn(EventSource.EVENTLOG, EventKind.PROCESS_CREATE, p.time,
                           Path(image).name if image else None, image, _int(d.get("NewProcessId")),
                           _int(d.get("ProcessId")), d.get("CommandLine") or None, raw_ref=f"Security:{p.record_id}",
                           details={"parent_image": parent, "parent_name": Path(parent).name if parent else None})


def defender_event(p: ParsedEvent) -> SecurityEventIn | None:
    if p.event_id not in (1116, 1117):
        return None
    d = p.data
    path = (d.get("Path") or "").split(";")[0]
    for prefix in ("file:_", "containerfile:_", "process:_"):
        if path.lower().startswith(prefix):
            path = path[len(prefix):]
    proc = d.get("Process Name") or None
    return SecurityEventIn(
        EventSource.EVENTLOG, EventKind.AV_DETECTION, p.time, Path(proc).name if proc and proc != "Unknown" else None,
        proc if proc and proc != "Unknown" else None, target_path=path or None, raw_ref=f"Defender:{p.record_id}",
        details={"product": "Microsoft Defender", "event_id": p.event_id, "threat_name": d.get("Threat Name"),
                 "severity": d.get("Severity Name"), "action": d.get("Action Name"),
                 "detection_user": d.get("Detection User")},
    )


QueryFn = Callable[..., list[str]]


class EventLogCollector:
    def __init__(self, name: str, channel: str, source: EventSource, event_ids: tuple[int, ...],
                 convert: Callable[[ParsedEvent], SecurityEventIn | None], *, admin_hint: str = "",
                 missing_hint: str = "此事件頻道不存在。", ignore_self: bool = True,
                 query: QueryFn = wevt.query_xml) -> None:
        self.name = name
        self.source = source
        self._channel = channel
        self._ids = event_ids
        self._convert = convert
        self._admin_hint = admin_hint
        self._missing_hint = missing_hint
        self._ignore_self = ignore_self
        self._query = query
        self._cursor = 0
        self._own = os.getpid()

    def status(self) -> CollectorStatus:
        try:
            self._query(self._channel, "*", reverse=True, max_events=1)
        except wevt.EventLogError as exc:
            if exc.code == wevt.ERROR_ACCESS_DENIED:
                return CollectorStatus(self.name, self.source, False,
                                       self._admin_hint or "需要系統管理員權限才能讀取。", True)
            if exc.code == wevt.ERROR_EVT_CHANNEL_NOT_FOUND:
                return CollectorStatus(self.name, self.source, False, self._missing_hint)
            return CollectorStatus(self.name, self.source, False, f"無法讀取事件記錄（錯誤 {exc.code}）。")
        return CollectorStatus(self.name, self.source, True, f"讀取事件頻道 {self._channel}")

    def start(self) -> None:
        latest = self._query(self._channel, "*", reverse=True, max_events=1)
        self._cursor = parse_event_xml(latest[0]).record_id if latest else 0

    def poll(self) -> list[SecurityEventIn]:
        ids = " or ".join(f"EventID={i}" for i in self._ids)
        xpath = f"*[System[EventRecordID>{self._cursor} and ({ids})]]"
        events = []
        for xml in self._query(self._channel, xpath, max_events=500):
            try:
                p = parse_event_xml(xml)
            except (ET.ParseError, ValueError):
                log.warning("unparseable event", extra={"ctx": {"channel": self._channel}})
                continue
            self._cursor = max(self._cursor, p.record_id)
            ev = self._convert(p)
            if ev is None:
                continue
            if self._ignore_self and (ev.ppid == self._own or ev.pid == self._own):
                continue
            events.append(ev)
        return events

    def stop(self) -> None:
        pass


def sysmon_collector(**kw) -> EventLogCollector:  # type: ignore[no-untyped-def]
    return EventLogCollector("Sysmon", "Microsoft-Windows-Sysmon/Operational", EventSource.SYSMON,
                             (1, 3, 11, 23, 26), sysmon_event,
                             admin_hint="Sysmon 日誌需要系統管理員權限才能讀取，請以系統管理員模式重新啟動。",
                             missing_hint="Sysmon 尚未安裝。可參考「Sysmon 設定指南」自行安裝。", **kw)


def security_log_collector(**kw) -> EventLogCollector:  # type: ignore[no-untyped-def]
    return EventLogCollector("Windows 安全性記錄（4688）", "Security", EventSource.EVENTLOG, (4688,), security_event,
                             admin_hint="安全性記錄需要系統管理員權限；另需在本機原則啟用「稽核程序建立」才會有 4688 事件。",
                             **kw)


def defender_collector(**kw) -> EventLogCollector:  # type: ignore[no-untyped-def]
    return EventLogCollector("Microsoft Defender 偵測", "Microsoft-Windows-Windows Defender/Operational",
                             EventSource.EVENTLOG, (1116, 1117), defender_event,
                             missing_hint="找不到 Microsoft Defender 的事件頻道。", **kw)
