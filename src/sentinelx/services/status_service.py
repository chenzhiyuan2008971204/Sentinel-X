"""Reports real application health for the Dashboard. Every value comes from a live check."""

from __future__ import annotations

import platform
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelx import __version__
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.core.models import EngineStatus
from sentinelx.engines.base import DetectionEngine
from sentinelx.storage.audit import AuditLog, ChainCheck
from sentinelx.storage.db import Database


@dataclass(frozen=True)
class SystemStatus:
    app_version: str
    python_version: str
    data_root: Path
    database_path: Path
    schema_version: int
    database_integrity_ok: bool
    audit_chain: ChainCheck
    privilege: PrivilegeLevel
    engines: tuple[EngineStatus, ...]

    @property
    def available_engines(self) -> tuple[EngineStatus, ...]:
        return tuple(e for e in self.engines if e.available)


class StatusService:
    def __init__(
        self,
        data_root: Path,
        db: Database,
        audit: AuditLog,
        privilege: PrivilegeLevel,
        engines: Sequence[DetectionEngine] = (),
    ) -> None:
        self._root = data_root
        self._db = db
        self._audit = audit
        self._privilege = privilege
        self._engines = list(engines)

    def snapshot(self) -> SystemStatus:
        return SystemStatus(
            app_version=__version__,
            python_version=platform.python_version(),
            data_root=self._root,
            database_path=self._db.path,
            schema_version=self._db.schema_version(),
            database_integrity_ok=self._db.integrity_ok(),
            audit_chain=self._audit.verify(),
            privilege=self._privilege,
            engines=tuple(e.availability() for e in self._engines),
        )
