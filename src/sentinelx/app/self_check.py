"""Notice when Sentinel X itself was interfered with (engineering audit 8, H4).

Sentinel X runs as the signed-in user, without a service or a kernel driver, so any program
running as that user can stop it, change its settings or remove its start-at-sign-in entry.
That cannot be prevented here; what is done instead is that it never goes unnoticed:

- A small marker file exists while Sentinel X runs and is removed when it closes normally.
  Found at the next start: the previous session ended unexpectedly (ended by another program,
  crashed, or the computer lost power).
- Every time Sentinel X saves its settings, the SHA-256 of the file is written to the audit log,
  whose entries are chained by hashes. At start the file is compared with the last recorded
  value; a difference means another program (or a person with a text editor) changed it.
- The start-at-sign-in entry is restored at start when it is missing (see main.py) and reported
  here when it had been removed although the setting asks for it.

Warnings are zh-TW texts for the user; each is also recorded in the audit log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from sentinelx.core.enums import AuditActor
from sentinelx.storage.audit import AuditLog

log = logging.getLogger(__name__)
MARKER = "session.running"


def file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


class SelfCheck:
    def __init__(self, root: Path, config_file: Path, audit: AuditLog) -> None:
        self._marker = root / MARKER
        self._config_file = config_file
        self._audit = audit
        self.warnings: list[tuple[str, str]] = []  # (title, message) for the user
        self.first_run = False  # no earlier start recorded: nothing to compare with
        self.config_sha256: str | None = None  # recorded in APP_START: the next start compares with it

    # ---- settings file ----
    def config_saved(self, data: bytes) -> None:
        """Called by ConfigStore after every save."""
        self._audit.record("CONFIG_SAVED", detail={"sha256": hashlib.sha256(data).hexdigest()})

    def _check_config(self) -> None:
        # The last known value: a save by Sentinel X, or the value recorded at the last start.
        current = file_sha256(self._config_file)
        self.config_sha256 = current
        last = self._audit.last_detail("CONFIG_SAVED", "APP_START")
        if current is None or last is None:
            return
        expected = last.get("sha256") or last.get("config_sha256")
        if expected and expected != current:
            self._audit.record("CONFIG_CHANGED_EXTERNALLY", detail={"expected": expected, "found": current})
            self.warnings.append(("設定檔被其他程式修改",
                                  "Sentinel X 的設定在它沒有執行時被改過（可能是其他程式，也可能是你自己用文字編輯器改的）。"
                                  "請到「即時防護」和「設定」確認防護選項是否如你所願。"))

    # ---- unexpected end ----
    def _check_previous_end(self) -> None:
        if not self._marker.exists():
            return
        try:
            info = json.loads(self._marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            info = {}
        self._audit.record("PREVIOUS_SESSION_UNEXPECTED_END", detail={"started": info.get("started"), "pid": info.get("pid")})
        self.warnings.append(("Sentinel X 上次沒有正常結束",
                              "上次 Sentinel X 是被其他程式結束、當機，或電腦斷電；那段時間防護可能沒有運作。"
                              "如果你沒有自己結束它，建議執行一次快速掃描。"))

    def start(self, started_at: str) -> list[tuple[str, str]]:
        """Run the checks once at start-up, then mark this session as running."""
        self._check_previous_end()
        self._check_config()
        try:
            tmp = self._marker.with_suffix(".tmp")
            tmp.write_text(json.dumps({"pid": os.getpid(), "started": started_at}), encoding="utf-8")
            os.replace(tmp, self._marker)
        except OSError:
            log.warning("cannot write the session marker", exc_info=True)
        return self.warnings

    def autostart_restored(self) -> None:
        self._audit.record("AUTOSTART_RESTORED", actor=AuditActor.SYSTEM)
        self.warnings.append(("開機自動啟動被移除了",
                              "Sentinel X 的「登入 Windows 時自動啟動」設定被移除了，已經恢復。"
                              "如果不是你移除的，可能有程式想讓 Sentinel X 下次開機不要執行。"))

    def end(self) -> None:
        """Normal close: remove the marker."""
        try:
            self._marker.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            log.warning("cannot remove the session marker", exc_info=True)
