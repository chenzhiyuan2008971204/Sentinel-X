"""Settings use cases: read, validate and save the configuration.

The saved values are copied into the shared `AppConfig` object, so services that save the
config themselves (watched folders) keep them. Most services read their settings when they
are built, so scan, engine and log settings take effect after a restart; monitor settings
take effect the next time monitoring starts. The page says which is which.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.app.paths import AppPaths
from sentinelx.core.enums import AuditActor
from sentinelx.storage.audit import AuditLog

# Fields this page never edits: always taken from the live configuration.
_KEEP = ("schema_version", "language", "signature_updates_consented", "signature_updates_prompted")
LABELS = {
    "scan.max_file_size_mb": "單檔大小上限（MB）", "scan.max_depth": "最大資料夾深度",
    "scan.max_files_per_job": "每次掃描檔案上限", "scan.engine_timeout_s": "引擎逾時（秒）",
    "scan.yara_timeout_s": "YARA 比對逾時（秒）", "scan.follow_reparse_points": "跟隨符號連結與交接點",
    "clamav.backend": "ClamAV 執行方式", "clamav.clamscan_path": "clamscan.exe 路徑",
    "clamav.database_dir": "病毒碼資料夾", "clamav.clamd_host": "clamd 主機", "clamav.clamd_port": "clamd 連接埠",
    "engines.clamav": "啟用 ClamAV", "engines.yara": "啟用 YARA", "engines.hash_intel": "啟用雜湊情報",
    "engines.pe_static": "啟用 PE 靜態分析", "monitor.poll_interval_s": "輪詢間隔（秒）",
    "monitor.retention_events": "保留事件數", "monitor.processes": "監控程序", "monitor.network": "監控網路連線",
    "monitor.folders": "監看資料夾", "monitor.sysmon": "讀取 Sysmon", "monitor.security_log": "讀取安全性記錄",
    "monitor.defender_log": "讀取 Defender 記錄", "log_level": "記錄等級",
}
_ERR = {
    "greater_than_equal": "不能小於 {ge}", "less_than_equal": "不能大於 {le}", "int_parsing": "必須是整數",
    "float_parsing": "必須是數字", "literal_error": "不是允許的選項", "too_long": "項目太多",
}


def _flat(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flat(v, key + "."))
        else:
            out[key] = v
    return out


def _messages(exc: ValidationError) -> str:
    parts = []
    for e in exc.errors():
        key = ".".join(str(x) for x in e["loc"])
        label = LABELS.get(key, key)
        if e["type"] == "value_error" and "loopback" in str(e.get("msg", "")):
            text = "只能是本機位址（127.0.0.1、::1 或 localhost），Sentinel X 不會連到其他電腦的 clamd"
        else:
            text = _ERR.get(e["type"], str(e.get("msg", "值不正確"))).format(**(e.get("ctx") or {}))
        parts.append(f"{label}：{text}")
    return "；".join(parts)


class SettingsService:
    RESTART_SECTIONS = ("scan", "clamav", "engines", "log_level")

    def __init__(self, paths: AppPaths, store: ConfigStore, config: AppConfig, audit: AuditLog) -> None:
        self._paths = paths
        self._store = store
        self._config = config
        self._audit = audit
        self.restart_pending = False

    @property
    def data_root(self) -> Path:
        return self._paths.root

    @property
    def log_dir(self) -> Path:
        return self._paths.log_dir

    def current(self) -> AppConfig:
        return self._config.model_copy(deep=True)

    @staticmethod
    def defaults() -> AppConfig:
        return AppConfig()

    def save(self, new: AppConfig) -> list[str]:
        """Validate and save. Returns the changed setting keys (empty: nothing to save).
        Raises ValueError with a Chinese message for invalid values."""
        data = new.model_dump()
        live = self._config
        for k in _KEEP:
            data[k] = getattr(live, k)
        data["monitor"]["watch_dirs"] = list(live.monitor.watch_dirs)  # edited on the monitor page
        c = data["clamav"]
        for key in ("clamscan_path", "database_dir"):
            c[key] = (c[key] or "").strip() or None
        if c["clamscan_path"] and not Path(c["clamscan_path"]).is_file():
            raise ValueError(f"{LABELS['clamav.clamscan_path']}：找不到這個檔案")
        if c["database_dir"] and not Path(c["database_dir"]).is_dir():
            raise ValueError(f"{LABELS['clamav.database_dir']}：資料夾不存在")
        try:
            validated = AppConfig.model_validate(data)
        except ValidationError as exc:
            raise ValueError(_messages(exc)) from exc
        before, after = _flat(live.model_dump()), _flat(validated.model_dump())
        changed = [k for k in after if before.get(k) != after[k]]
        if not changed:
            return []
        self._store.save(validated)
        for name in type(validated).model_fields:  # keep the shared object in step with the file
            setattr(live, name, getattr(validated, name))
        if any(k.split(".")[0] in self.RESTART_SECTIONS for k in changed):
            self.restart_pending = True
        self._audit.record("SETTINGS_CHANGE", actor=AuditActor.USER, subject="config.json",
                           detail={k: [before.get(k), after[k]] for k in changed})
        return changed
