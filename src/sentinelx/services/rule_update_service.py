"""Public YARA rules from YARA Forge (github.com/YARAHQ/yara-forge), only with consent.

YARA Forge collects rules from many security research teams, tests them and publishes
packages; the "core" package is the one with the fewest false positives. Sentinel X:
  1. reads the latest release from the GitHub API (tag, file size and SHA-256 digest),
  2. downloads yara-forge-rules-core.zip and checks its size and SHA-256 against that,
  3. extracts the single .yar file from memory (no paths from the archive are used),
  4. adds it like any user rule set (safe modules only, no include, compiled before use),
  5. disables the previous version.
It checks once a week while Sentinel X runs, and on request. Nothing is executed.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.core.enums import AuditActor
from sentinelx.services.intel_service import IntelService
from sentinelx.storage.audit import AuditLog

API_LATEST = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
ASSET = "yara-forge-rules-core.zip"
DOWNLOAD_PREFIX = "https://github.com/YARAHQ/yara-forge/releases/download/"
MEMBER = "packages/core/yara-rules-core.yar"
RULE_SET_NAME = "YARA Forge core"
MAX_ZIP_BYTES = 32 * 1024 * 1024
MAX_YAR_BYTES = 16 * 1024 * 1024
CHECK_EVERY = timedelta(days=7)
TS = "%Y-%m-%dT%H:%M:%SZ"
Opener = Callable[..., Any]


class RuleUpdateError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RuleUpdateService:
    def __init__(self, config: AppConfig, store: ConfigStore, audit: AuditLog, intel: IntelService,
                 *, opener: Opener = urllib.request.urlopen, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._config = config
        self._store = store
        self._audit = audit
        self._intel = intel
        self._open = opener
        self._now = now
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.on_result: Callable[[str, str], None] = lambda _level, _msg: None

    # ---- state ----
    @property
    def consented(self) -> bool:
        return self._config.yara_forge.consented

    def installed(self) -> tuple[str, int] | None:
        """(version, rule count) of the enabled YARA Forge rule set."""
        for r in self._intel.rule_sets():
            if r.name.startswith(RULE_SET_NAME) and r.enabled:
                return r.version, r.rule_count
        return None

    def set_consent(self, on: bool) -> None:
        self._config.yara_forge.consented = on
        self._store.save(self._config)
        self._audit.record("YARA_FORGE_CONSENT", actor=AuditActor.USER, detail={"consent": on})

    def due(self) -> bool:
        if not self.consented:
            return False
        last = self._config.yara_forge.last_check
        if not last:
            return True
        try:
            return self._now() - datetime.strptime(last, TS).replace(tzinfo=UTC) >= CHECK_EVERY
        except ValueError:
            return True

    # ---- network ----
    def _get(self, url: str, limit: int) -> bytes:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "SentinelX-rule-updater"})
        try:
            with self._open(req, timeout=60) as resp:
                data = resp.read(limit + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuleUpdateError("無法連線到 GitHub（網路問題）") from exc
        if len(data) > limit:
            raise RuleUpdateError("下載內容超過大小上限，已放棄")
        return data

    def latest(self) -> dict[str, Any]:
        try:
            rel = json.loads(self._get(API_LATEST, 2 * 1024 * 1024).decode("utf-8"))
            asset = next(a for a in rel["assets"] if a["name"] == ASSET)
            digest = str(asset.get("digest") or "")
            if not digest.startswith("sha256:"):
                raise RuleUpdateError("GitHub 沒有提供檔案的 SHA-256，為了安全不下載")
            url = str(asset["browser_download_url"])
            if not url.startswith(DOWNLOAD_PREFIX):  # audit 8, L3
                raise RuleUpdateError("下載位址不是 YARA Forge 在 GitHub 的官方位置，為了安全不下載")
            return {"version": str(rel["tag_name"]), "url": url,
                    "size": int(asset["size"]), "sha256": digest.split(":", 1)[1].lower()}
        except (KeyError, StopIteration, ValueError, TypeError) as exc:
            raise RuleUpdateError("GitHub 回應格式無法解讀") from exc

    # ---- update ----
    def update(self, *, actor: AuditActor = AuditActor.USER) -> str:
        """Install the latest YARA Forge core rules if newer. Returns a message (zh-TW)."""
        if not self.consented:
            raise RuleUpdateError("尚未同意下載 YARA 規則")
        if not self._lock.acquire(blocking=False):
            raise RuleUpdateError("規則正在更新中")
        try:
            return self._update(actor)
        finally:
            self._config.yara_forge.last_check = self._now().strftime(TS)
            self._store.save(self._config)
            self._lock.release()

    def _update(self, actor: AuditActor) -> str:
        info = self.latest()
        cur = self.installed()
        if cur and cur[0] == info["version"]:
            return f"YARA 規則已是最新版（{info['version']}，{cur[1]} 條）。"
        if info["size"] > MAX_ZIP_BYTES:
            raise RuleUpdateError("規則檔異常地大，已放棄")
        data = self._get(info["url"], MAX_ZIP_BYTES)
        if len(data) != info["size"] or hashlib.sha256(data).hexdigest() != info["sha256"]:
            raise RuleUpdateError("下載的檔案和 GitHub 公布的 SHA-256 不符，已放棄（可能損壞或被竄改）")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                member = z.getinfo(MEMBER)
                if member.file_size > MAX_YAR_BYTES:
                    raise RuleUpdateError("規則檔超過 16 MB 上限")
                text = z.read(member)
        except (KeyError, zipfile.BadZipFile) as exc:
            raise RuleUpdateError("壓縮檔內容不是預期的 YARA Forge 格式") from exc
        with tempfile.TemporaryDirectory(prefix="sx-yara-forge-") as d:
            path = Path(d) / "yara-forge-core.yar"
            path.write_bytes(text)
            row = self._intel.add_rule_file(path, f"{RULE_SET_NAME} {info['version']}", info["version"])
        if not row.enabled:
            self._intel.remove_rule_set(row.id)  # registered disabled with the error; not kept
            raise RuleUpdateError(f"新規則沒有通過檢查，保留原本的規則：{row.validation_error}")
        for r in self._intel.rule_sets():
            if r.name.startswith(RULE_SET_NAME) and r.id != row.id:
                self._intel.remove_rule_set(r.id)  # the previous version (Sentinel X's own copy)
        self._config.yara_forge.version = info["version"]
        self._audit.record("YARA_FORGE_UPDATE", actor=actor, detail={"version": info["version"], "rules": row.rule_count,
                                                                    "sha256": info["sha256"]})
        return f"已更新 YARA 規則到 {info['version']}（{row.rule_count} 條）。"

    # ---- weekly background check ----
    def start_auto(self, *, check_s: float = 6 * 3600, first_delay_s: float = 90.0) -> None:
        if self._thread is not None:
            return
        self._stop.clear()

        def loop() -> None:
            delay = first_delay_s
            while not self._stop.wait(delay):
                delay = check_s
                if not self.due():
                    continue
                try:
                    msg = self.update(actor=AuditActor.SYSTEM)
                    if msg.startswith("已更新"):
                        self.on_result("info", msg)
                except RuleUpdateError as exc:
                    self.on_result("warn", f"YARA 規則自動更新失敗：{exc.reason}")
                except Exception:  # noqa: BLE001 - never let the thread die
                    logging.getLogger(__name__).exception("YARA Forge update failed")

        self._thread = threading.Thread(target=loop, name="sentinelx-yara-forge", daemon=True)
        self._thread.start()

    def stop_auto(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(10)
            self._thread = None
