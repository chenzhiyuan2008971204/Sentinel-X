"""Filesystem locations used by the application.

Everything lives under one per-user data root so the app never needs elevation to write:
`%LOCALAPPDATA%\\SentinelX` by default, or `SENTINELX_HOME` when set (used by tests).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

HOME_ENV = "SENTINELX_HOME"


@dataclass(frozen=True)
class AppPaths:
    root: Path

    @property
    def config_file(self) -> Path:
        return self.root / "config.json"

    @property
    def database_file(self) -> Path:
        return self.root / "sentinelx.db"

    @property
    def log_dir(self) -> Path:
        return self.root / "logs"

    @property
    def vault_dir(self) -> Path:
        return self.root / "vault"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def yara_rules_dir(self) -> Path:
        return self.root / "rules" / "yara"

    @classmethod
    def default(cls) -> AppPaths:
        override = os.environ.get(HOME_ENV)
        if override:
            return cls(Path(override).resolve())
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return cls(Path(base) / "SentinelX")

    def ensure(self) -> None:
        """Create the directories the application writes to.

        The vault directory is created here; its ACL is hardened and verified by
        `QuarantineVault` on every start.
        """
        for d in (self.root, self.log_dir, self.vault_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
