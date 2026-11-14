"""Security events and alerts. Events are append-only (pruned only by the retention limit);
alerts are de-duplicated by key while open."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, or_, select

from sentinelx.core.enums import AlertStatus, EventSource, Severity
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.monitor.events import EventKind, SecurityEventIn, StoredEvent
from sentinelx.storage.db import Database
from sentinelx.storage.orm import Alert, SecurityEvent

DEDUP_WINDOW = timedelta(minutes=10)


@dataclass(frozen=True)
class AlertIn:
    rule_id: str
    title: str
    severity: Severity
    observed_facts: list[str]  # what was recorded, verbatim
    analysis: str  # interpretation, clearly separate from facts
    event_ids: list[int]
    dedup_key: str


@dataclass(frozen=True)
class AlertRow:
    id: int
    created_at: str
    updated_at: str | None
    rule_id: str | None
    title: str
    severity: Severity
    observed_facts: list[str]
    analysis: str
    event_ids: list[int]
    status: AlertStatus


def _to_stored(e: SecurityEvent) -> StoredEvent:
    return StoredEvent(
        EventSource(e.source), EventKind(e.kind), e.occurred_at, e.process_name, e.process_path, e.pid, e.ppid,
        e.command_line, e.target_path, e.remote_addr, e.remote_port, e.sha256, e.raw_ref,
        json.loads(e.details_json or "{}"), id=e.id,
    )


def _to_alert(a: Alert) -> AlertRow:
    return AlertRow(a.id, a.created_at, a.updated_at, a.rule_id, a.title, Severity(a.severity),
                    json.loads(a.observed_facts or "[]"), a.analytic_notes or "", json.loads(a.event_ids or "[]"),
                    AlertStatus(a.status))


class EventRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ---------- events ----------
    def insert(self, events: list[SecurityEventIn]) -> list[StoredEvent]:
        if not events:
            return []
        out: list[StoredEvent] = []
        with self._db.session() as s:
            rows = []
            for ev in events:
                r = SecurityEvent(
                    source=ev.source.value, kind=ev.kind.value, occurred_at=ev.occurred_at,
                    process_name=ev.process_name, process_path=ev.process_path, pid=ev.pid, ppid=ev.ppid,
                    command_line=ev.command_line, target_path=ev.target_path, remote_addr=ev.remote_addr,
                    remote_port=ev.remote_port, sha256=ev.sha256, raw_ref=ev.raw_ref,
                    details_json=json.dumps(ev.details, ensure_ascii=False, default=str),
                )
                s.add(r)
                rows.append(r)
            s.flush()
            out = [_to_stored(r) for r in rows]
        return out

    def query(self, *, source: EventSource | None = None, kind: EventKind | None = None, text: str | None = None,
              limit: int = 500) -> list[StoredEvent]:
        with self._db.session() as s:
            q = select(SecurityEvent)
            if source is not None:
                q = q.where(SecurityEvent.source == source.value)
            if kind is not None:
                q = q.where(SecurityEvent.kind == kind.value)
            if text:
                like = f"%{text}%"
                q = q.where(or_(SecurityEvent.process_name.like(like), SecurityEvent.process_path.like(like),
                                SecurityEvent.command_line.like(like), SecurityEvent.target_path.like(like),
                                SecurityEvent.remote_addr.like(like)))
            q = q.order_by(SecurityEvent.id.desc()).limit(limit)
            return [_to_stored(e) for e in s.scalars(q)]

    def count(self) -> int:
        with self._db.session() as s:
            return int(s.scalar(select(func.count()).select_from(SecurityEvent)) or 0)

    def prune(self, keep: int) -> int:
        """Retention: keep the newest `keep` events. Alerts keep their facts as text."""
        with self._db.session() as s:
            cutoff = s.scalar(select(SecurityEvent.id).order_by(SecurityEvent.id.desc()).offset(keep).limit(1))
            if cutoff is None:
                return 0
            return int(s.execute(delete(SecurityEvent).where(SecurityEvent.id <= cutoff)).rowcount or 0)

    # ---------- alerts ----------
    def add_alert(self, a: AlertIn) -> tuple[int, bool]:
        """Insert, or merge into an open alert with the same key from the last 10 minutes.
        Returns (alert id, created)."""
        now = utc_now_iso()
        since = (datetime.now(UTC) - DEDUP_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._db.session() as s:
            existing = s.scalars(
                select(Alert).where(Alert.dedup_key == a.dedup_key, Alert.status == AlertStatus.OPEN.value,
                                    Alert.created_at >= since).order_by(Alert.id.desc()).limit(1)
            ).first()
            if existing is not None:
                ids = sorted(set(json.loads(existing.event_ids or "[]")) | set(a.event_ids))
                existing.event_ids = json.dumps(ids)
                existing.updated_at = now
                return existing.id, False
            row = Alert(created_at=now, updated_at=now, title=a.title,
                        observed_facts=json.dumps(a.observed_facts, ensure_ascii=False),
                        analytic_notes=a.analysis, severity=a.severity.value, event_ids=json.dumps(a.event_ids),
                        status=AlertStatus.OPEN.value, rule_id=a.rule_id, dedup_key=a.dedup_key)
            s.add(row)
            s.flush()
            return row.id, True

    def alerts(self, include_closed: bool = False, limit: int = 500) -> list[AlertRow]:
        with self._db.session() as s:
            q = select(Alert)
            if not include_closed:
                q = q.where(Alert.status == AlertStatus.OPEN.value)
            return [_to_alert(a) for a in s.scalars(q.order_by(Alert.id.desc()).limit(limit))]

    def set_alert_status(self, alert_id: int, status: AlertStatus) -> AlertRow | None:
        with self._db.session() as s:
            a = s.get(Alert, alert_id)
            if a is None:
                return None
            a.status = status.value
            a.updated_at = utc_now_iso()
            return _to_alert(a)

    def events_by_ids(self, ids: list[int]) -> list[StoredEvent]:
        if not ids:
            return []
        with self._db.session() as s:
            return [_to_stored(e) for e in s.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(ids))
                                                    .order_by(SecurityEvent.id))]

    def open_alert_count(self) -> int:
        with self._db.session() as s:
            return int(s.scalar(select(func.count()).select_from(Alert)
                                .where(Alert.status == AlertStatus.OPEN.value)) or 0)
