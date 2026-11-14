"""SQLite database lifecycle: engine creation, pragmas, schema init and health checks."""

from __future__ import annotations

import logging
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from sentinelx.core.errors import DatabaseError
from sentinelx.storage.orm import MIGRATIONS, SCHEMA_VERSION, Base, SchemaMeta

log = logging.getLogger(__name__)


def _apply_pragmas(dbapi_conn: Any, _record: Any) -> None:
    if not isinstance(dbapi_conn, sqlite3.Connection):
        return
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.close()


class Database:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._engine: Engine = create_engine(f"sqlite:///{path.as_posix()}", future=True)
        event.listen(self._engine, "connect", _apply_pragmas)
        self._sessions = sessionmaker(self._engine, expire_on_commit=False)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def engine(self) -> Engine:
        return self._engine

    def initialize(self) -> int:
        """Create tables if needed, migrate older schemas, and return the schema version.

        Before migrating an existing database a copy is saved next to it
        (`<name>.bak-v<old>`), so a failed migration never loses data.
        """
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            existing = self._read_version()
            if existing is not None and existing > SCHEMA_VERSION:
                raise DatabaseError(
                    f"database schema {existing} is newer than this build ({SCHEMA_VERSION})",
                    user_message="資料庫版本比程式新，請更新 Sentinel X。",
                )
            if existing is not None and existing < SCHEMA_VERSION:
                self._migrate(existing)
            Base.metadata.create_all(self._engine)
            with self.session() as s:
                row = s.get(SchemaMeta, "schema_version")
                if row is None:
                    s.add(SchemaMeta(key="schema_version", value=str(SCHEMA_VERSION)))
                else:
                    row.value = str(SCHEMA_VERSION)
        except (SQLAlchemyError, OSError, ValueError) as exc:
            raise DatabaseError(f"database init failed for {self._path}: {exc}") from exc
        log.info("database ready", extra={"ctx": {"path": str(self._path), "schema": SCHEMA_VERSION}})
        return SCHEMA_VERSION

    def _read_version(self) -> int | None:
        with self._engine.connect() as c:
            has_meta = c.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta'")
            ).first()
            if not has_meta:
                return None
            v = c.execute(text("SELECT value FROM schema_meta WHERE key='schema_version'")).scalar()
        return int(v) if v is not None else None

    def _migrate(self, from_version: int) -> None:
        backup = self._path.with_name(f"{self._path.name}.bak-v{from_version}")
        if not backup.exists():
            with self._engine.connect() as c:
                c.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
            shutil.copy2(self._path, backup)
        with self._engine.begin() as c:
            for v in range(from_version + 1, SCHEMA_VERSION + 1):
                for stmt in MIGRATIONS.get(v, []):
                    c.exec_driver_sql(stmt)
                c.execute(text("UPDATE schema_meta SET value=:v WHERE key='schema_version'"), {"v": str(v)})
                log.info("database migrated", extra={"ctx": {"to": v, "backup": str(backup)}})

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional session: commits on success, rolls back on any exception."""
        s = self._sessions()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def schema_version(self) -> int:
        with self.session() as s:
            v = s.scalar(select(SchemaMeta.value).where(SchemaMeta.key == "schema_version"))
        return int(v) if v is not None else 0

    def integrity_ok(self) -> bool:
        with self._engine.connect() as c:
            return c.execute(text("PRAGMA integrity_check")).scalar() == "ok"

    def dispose(self) -> None:
        self._engine.dispose()
