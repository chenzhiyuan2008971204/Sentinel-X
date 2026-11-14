"""Application configuration.

Stored as JSON in the data root. Unknown keys and invalid values are rejected rather than
silently ignored, and a broken file is never overwritten automatically so the user can
inspect it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinelx.core.errors import ConfigError

LOOPBACK_NAMES = {"localhost"}


class ScanLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_size_mb: int = Field(default=100, ge=1, le=4096)
    max_depth: int = Field(default=64, ge=1, le=1024)
    max_files_per_job: int = Field(default=1_000_000, ge=1)
    engine_timeout_s: int = Field(default=120, ge=1, le=3600)
    # One YARA match cannot be interrupted; a shorter limit keeps cancel/close responsive (audit R2).
    yara_timeout_s: int = Field(default=60, ge=1, le=3600)
    follow_reparse_points: bool = False


class ClamAVSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: Literal["clamscan", "clamd"] = "clamscan"
    clamscan_path: str | None = None
    # Signature DB folder. None = `<data root>\clamav-db` if it exists, else ClamAV's own default.
    database_dir: str | None = None
    clamd_host: str = "127.0.0.1"
    clamd_port: int = Field(default=3310, ge=1, le=65535)

    @field_validator("clamd_host")
    @classmethod
    def _loopback_only(cls, v: str) -> str:
        if v.lower() in LOOPBACK_NAMES:
            return v
        try:
            if ipaddress.ip_address(v).is_loopback:
                return v
        except ValueError:
            pass
        raise ValueError("clamd_host must be a loopback address (127.0.0.1, ::1 or localhost)")


class EngineToggles(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clamav: bool = True
    yara: bool = True
    hash_intel: bool = True
    pe_static: bool = True
    virustotal: bool = True  # used only after consent and with an API key


class MonitorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    watch_dirs: list[str] = Field(default_factory=list, max_length=50)
    poll_interval_s: float = Field(default=3.0, ge=1.0, le=60.0)
    retention_events: int = Field(default=200_000, ge=1_000, le=10_000_000)
    processes: bool = True
    network: bool = True
    folders: bool = True
    sysmon: bool = True
    security_log: bool = True
    defender_log: bool = True

    @field_validator("watch_dirs")
    @classmethod
    def _absolute(cls, v: list[str]) -> list[str]:
        for d in v:
            if not Path(d).is_absolute():
                raise ValueError(f"watch_dirs must be absolute paths: {d!r}")
        return v


class ProtectionSettings(BaseModel):
    """Real-time protection (user mode: scans new files after they are written; it cannot block
    a program before Windows starts it — that needs a kernel driver)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    auto_quarantine: bool = True  # CONFIRMED_THREAT only; never deletes
    kill_known_threats: bool = True  # terminate processes whose file hash is a confirmed or quarantined threat
    download_gate: bool = True  # verdict + signature + origin notification for new installers in Downloads
    exec_lock: bool = True  # new programs in Downloads cannot be started until checked (deny-execute ACE)
    start_at_login: bool = True
    watch_all_drives: bool = True  # every fixed drive (noisy system/cache paths skipped)
    low_memory: bool = False  # no resident ClamAV (~950 MB less); ClamAV only for brought-in files, per batch
    watch_autostart: bool = True  # report and scan programs newly set to start with Windows (read-only)
    ransomware_watch: bool = True  # warn when user files are changed in the typical encryption pattern
    ransomware_decoys: bool = False  # place harmless decoy documents in the user's folders (asks first)
    watch_downloads: bool = True
    watch_desktop_documents: bool = True
    watch_temp: bool = True
    watch_removable: bool = True


class VirusTotalSettings(BaseModel):
    """Hash lookups at VirusTotal. Off until the user agrees; the API key is stored separately,
    encrypted with Windows DPAPI (never in this file)."""

    model_config = ConfigDict(extra="forbid")

    consented: bool = False  # the user agreed that SHA-256 values may be sent to virustotal.com


class YaraForgeSettings(BaseModel):
    """Public YARA rules from YARA Forge, downloaded weekly only after consent."""

    model_config = ConfigDict(extra="forbid")

    consented: bool = False
    last_check: str | None = None
    version: str | None = None


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    language: Literal["zh_TW", "en"] = "zh_TW"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    scan: ScanLimits = Field(default_factory=ScanLimits)
    clamav: ClamAVSettings = Field(default_factory=ClamAVSettings)
    engines: EngineToggles = Field(default_factory=EngineToggles)
    monitor: MonitorSettings = Field(default_factory=MonitorSettings)
    protection: ProtectionSettings = Field(default_factory=ProtectionSettings)
    virustotal: VirusTotalSettings = Field(default_factory=VirusTotalSettings)
    yara_forge: YaraForgeSettings = Field(default_factory=YaraForgeSettings)
    signature_updates_consented: bool = False
    signature_updates_prompted: bool = False  # the first-run question was answered
    signature_auto_update: bool = True  # daily, only while consented and Sentinel X is running
    signature_last_attempt: str | None = None  # UTC ISO time of the last update attempt
    signature_last_success: str | None = None


class ConfigStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self.on_saved: Callable[[bytes], None] | None = None  # e.g. record the file's hash (self_check)

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> AppConfig:
        """Load config, creating defaults on first run."""
        if not self._path.exists():
            cfg = AppConfig()
            self.save(cfg)
            return cfg
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read {self._path}: {exc}") from exc
        try:
            return AppConfig.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"invalid config {self._path}: {exc}") from exc

    def save(self, cfg: AppConfig) -> None:
        """Atomic write: temp file in the same directory, then replace."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        data = cfg.model_dump_json(indent=2).encode("utf-8")
        tmp.write_bytes(data)
        os.replace(tmp, self._path)
        if self.on_saved is not None:
            self.on_saved(data)
