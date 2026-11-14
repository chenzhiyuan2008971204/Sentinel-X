"""Hash-chained audit log.

Each entry stores the previous entry's hash and its own hash over a canonical encoding.
This makes edits, deletions and reordering detectable; it does not prevent them
(see SECURITY_DESIGN.md §6).
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select, text

from sentinelx.core.enums import AuditActor
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.db import Database
from sentinelx.storage.orm import AuditEntry

GENESIS_HASH = "0" * 64
FULL_VERIFY_INTERVAL_S = 600.0  # incremental checks in between (audit R4)


def _entry_hash(prev_hash: str, at: str, actor: str, action: str, subject: str, detail_json: str) -> str:
    canonical = json.dumps(
        [prev_hash, at, actor, action, subject, detail_json], ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainCheck:
    ok: bool
    entries: int
    first_bad_id: int | None = None
    reason: str | None = None


class AuditLog:
    def __init__(self, db: Database, *, full_interval_s: float = FULL_VERIFY_INTERVAL_S,
                 clock: Any = time.monotonic) -> None:
        self._db = db
        self._lock = threading.Lock()
        self._verify_lock = threading.Lock()
        self._full_interval_s = full_interval_s
        self._clock = clock
        # (last verified id, its hash, entries up to it, clock of the last full pass)
        self._checkpoint: tuple[int, str, int, float] | None = None

    def record(
        self,
        action: str,
        *,
        actor: AuditActor = AuditActor.SYSTEM,
        subject: str = "",
        detail: dict[str, Any] | None = None,
    ) -> int:
        detail_json = json.dumps(detail or {}, ensure_ascii=False, sort_keys=True, default=str)
        with self._lock, self._db.session() as s:
            # The thread lock only covers this process. Take SQLite's write lock *before* reading
            # the last hash (a no-op write is the first statement of the transaction), so another
            # process cannot append between our read and our insert and fork the chain.
            s.execute(text("UPDATE schema_meta SET value = value WHERE key = 'schema_version'"))
            last = s.scalar(select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1))
            prev = last or GENESIS_HASH
            at = utc_now_iso()
            entry = AuditEntry(
                at=at,
                actor=actor.value,
                action=action,
                subject=subject,
                detail_json=detail_json,
                prev_hash=prev,
                entry_hash=_entry_hash(prev, at, actor.value, action, subject, detail_json),
            )
            s.add(entry)
            s.flush()
            return entry.id

    def last_detail(self, *actions: str) -> dict[str, Any] | None:
        """Detail of the newest entry with one of these actions, or None."""
        with self._db.session() as s:
            raw = s.scalar(select(AuditEntry.detail_json).where(AuditEntry.action.in_(actions))
                           .order_by(AuditEntry.id.desc()).limit(1))
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    def entry(self, entry_id: int) -> tuple[str, dict[str, Any]] | None:
        """(action, detail) of one entry, only if its own hash is intact and the chain verifies."""
        if not self.verify().ok:
            return None
        with self._db.session() as s:
            e = s.get(AuditEntry, entry_id)
            if e is None:
                return None
            return e.action, json.loads(e.detail_json or "{}")

    def verify(self, *, full: bool = False) -> ChainCheck:
        """Check the hash chain.

        A full pass re-hashes every entry. Between full passes (at most `full_interval_s` apart)
        only entries added since the last verified one are hashed, after checking that the
        last verified entry is unchanged and that no entry before it was removed. An edit to an
        older entry's content is therefore found by the next full pass, not immediately.
        """
        with self._verify_lock:
            cp = self._checkpoint
            if full or cp is None or self._clock() - cp[3] >= self._full_interval_s:
                return self._verify_from(None)
            return self._verify_from(cp)

    def _verify_from(self, cp: tuple[int, str, int, float] | None) -> ChainCheck:
        prev, count, after_id = GENESIS_HASH, 0, 0
        with self._db.session() as s:
            if cp is not None:
                after_id, cp_hash, cp_count, _ = cp
                e = s.get(AuditEntry, after_id)
                before = s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.id <= after_id))
                if (e is None or e.entry_hash != cp_hash or before != cp_count
                        or _entry_hash(e.prev_hash, e.at, e.actor, e.action, e.subject, e.detail_json) != cp_hash):
                    self._checkpoint = None
                    return self._verify_from(None)  # something before the checkpoint changed: find it
                prev, count = cp_hash, cp_count
            last_id = after_id
            for e in s.scalars(select(AuditEntry).where(AuditEntry.id > after_id).order_by(AuditEntry.id)):
                count += 1
                if e.prev_hash != prev:
                    self._checkpoint = None
                    return ChainCheck(False, count, e.id, "prev_hash does not match previous entry")
                expected = _entry_hash(e.prev_hash, e.at, e.actor, e.action, e.subject, e.detail_json)
                if e.entry_hash != expected:
                    self._checkpoint = None
                    return ChainCheck(False, count, e.id, "entry content does not match its hash")
                prev, last_id = e.entry_hash, e.id
        full_at = self._clock() if cp is None else cp[3]
        self._checkpoint = (last_id, prev, count, full_at) if count else None
        return ChainCheck(True, count)
