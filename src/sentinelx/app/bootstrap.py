"""Composition root. The only place that wires concrete implementations together."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelx import __version__
from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.app.logging_setup import configure_logging
from sentinelx.app.paths import AppPaths
from sentinelx.app.privilege import detect_privilege
from sentinelx.core.enums import AuditActor, PrivilegeLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.clamav import ClamAVEngine, is_bundled, locate_clamscan
from sentinelx.engines.clamd import ClamdEngine
from sentinelx.engines.hash_intel import HashIntelEngine
from sentinelx.engines.pe_static import PEStaticEngine
from sentinelx.engines.yara_engine import YaraEngine
from sentinelx.services.intel_service import IntelService
from sentinelx.services.lab_service import LabService
from sentinelx.services.monitor_service import MonitorService
from sentinelx.services.report_service import ReportService
from sentinelx.services.settings_service import SettingsService
from sentinelx.services.signature_service import SignatureService
from sentinelx.services.virustotal_service import VirusTotalService
from sentinelx.services.rule_update_service import RuleUpdateService
from sentinelx.services.sandbox_service import SandboxService
from sentinelx.sandbox.trial import Sandbox
from sentinelx.core.secret_store import SecretFile
from sentinelx.engines.virustotal import VirusTotalEngine, VtClient
from sentinelx.services.protection_service import ProtectionService
from sentinelx.protection.clamd_manager import ClamdManager
from sentinelx.storage.scan_repository import ExclusionRepository
from sentinelx.storage.report_repository import ReportRepository
from sentinelx.storage.research_repository import ResearchRepository
from sentinelx.storage.event_repository import EventRepository
from sentinelx.quarantine.vault import QuarantineVault
from sentinelx.services.quarantine_service import QuarantineService
from sentinelx.services.review_service import ReviewService
from sentinelx.services.scan_service import ScanService
from sentinelx.services.static_analysis_service import StaticAnalysisService
from sentinelx.services.status_service import StatusService
from sentinelx.app.self_check import SelfCheck
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.db import Database
from sentinelx.storage.intel_repository import IntelStore
from sentinelx.storage.rules_repository import RuleSetStore
from sentinelx.storage.scan_repository import REALTIME_KEEP_DAYS, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

log = logging.getLogger(__name__)


@dataclass
class AppContainer:
    paths: AppPaths
    config_store: ConfigStore
    config: AppConfig
    db: Database
    audit: AuditLog
    privilege: PrivilegeLevel
    engines: list[DetectionEngine]
    status: StatusService
    scans: ScanService
    intel: IntelService
    static: StaticAnalysisService
    reviews: ReviewService
    quarantine: QuarantineService
    monitor: MonitorService
    reports: ReportService
    lab: LabService
    settings: SettingsService
    signatures: SignatureService
    protection: ProtectionService
    virustotal: VirusTotalService
    sandbox: SandboxService
    rule_updates: RuleUpdateService
    self_check: SelfCheck | None = None

    def shutdown(self) -> None:
        self.signatures.stop_auto()
        self.rule_updates.stop_auto()
        self.protection.stop()
        self.monitor.stop()
        self.audit.record("APP_STOP")
        if self.self_check is not None:
            self.self_check.end()
        self.db.dispose()


def clamav_database_dir(config: AppConfig, paths: AppPaths, clamscan: Path | None = None) -> Path | None:
    """Configured folder; else `<data root>/clamav-db` if it exists, or always for the bundled
    ClamAV (its own default folder is inside the read-only program folder); else ClamAV's default."""
    if config.clamav.database_dir:
        return Path(config.clamav.database_dir)
    per_user = paths.root / "clamav-db"
    return per_user if per_user.is_dir() or is_bundled(clamscan) else None


def _signatures_updated(engines: Sequence[DetectionEngine]) -> Callable[[Path], None]:
    """After a successful update: point the ClamAV engine at the new folder and re-check it."""
    def apply(db_dir: Path) -> None:
        for e in engines:
            if isinstance(e, ClamAVEngine):
                if e.database_dir is None:
                    e.set_database_dir(db_dir)
                e.availability(refresh=True)
    return apply


def _clamav_ready(engines: Sequence[DetectionEngine]) -> Callable[[], bool]:
    def ready() -> bool:
        return any(e.name == "ClamAV" and e.availability().available for e in engines)
    return ready


def build_clamd(config: AppConfig, paths: AppPaths) -> ClamdManager | None:
    """Resident clamd for real-time protection; None when the user runs their own clamd backend."""
    if config.clamav.backend == "clamd" or not config.engines.clamav:
        return None
    exe = locate_clamscan(config.clamav.clamscan_path)
    clamd = exe.with_name("clamd.exe") if exe is not None else None
    db_dir = clamav_database_dir(config, paths, exe) or paths.root / "clamav-db"
    return ClamdManager(clamd, db_dir, paths.root / "clamd", max_file_mb=config.scan.max_file_size_mb)


def build_clamav(config: AppConfig, paths: AppPaths) -> DetectionEngine:
    c = config.clamav
    if c.backend == "clamd":
        return ClamdEngine(c.clamd_host, c.clamd_port, timeout_s=config.scan.engine_timeout_s)
    exe = locate_clamscan(c.clamscan_path)
    return ClamAVEngine(
        exe,
        timeout_s=config.scan.engine_timeout_s,
        max_file_size_mb=config.scan.max_file_size_mb,
        database_dir=clamav_database_dir(config, paths, exe),
    )


def build_engines(config: AppConfig, paths: AppPaths, intel: IntelStore, rules: RuleSetStore) -> list[DetectionEngine]:
    t = config.engines
    lim = config.scan
    engines: list[DetectionEngine] = []
    if t.clamav:
        engines.append(build_clamav(config, paths))
    if t.yara:
        engines.append(YaraEngine(rules, timeout_s=lim.yara_timeout_s, max_file_size_mb=lim.max_file_size_mb))
    if t.hash_intel:
        engines.append(HashIntelEngine(intel))
    if t.pe_static:
        engines.append(PEStaticEngine())
    return engines


def bootstrap(
    paths: AppPaths | None = None,
    *,
    console_log: bool = True,
    privilege: PrivilegeLevel | None = None,
    engines: Sequence[DetectionEngine] | None = None,
) -> AppContainer:
    paths = paths or AppPaths.default()
    paths.ensure()

    store = ConfigStore(paths.config_file)
    config = store.load()
    configure_logging(paths.log_dir, config.log_level, console=console_log)

    db = Database(paths.database_file)
    db.initialize()
    audit = AuditLog(db)

    chain = audit.verify()
    if not chain.ok:
        # Reported on the Dashboard; we keep running so the user can investigate.
        log.error("audit chain broken", extra={"ctx": {"first_bad_id": chain.first_bad_id, "reason": chain.reason}})

    interrupted = ScanRepository(db).mark_interrupted_jobs()
    if interrupted:
        audit.record("SCAN_INTERRUPTED", detail={"jobs": interrupted})
        log.warning("closed interrupted scan jobs", extra={"ctx": {"count": interrupted}})
    pruned = ScanRepository(db).prune_realtime()
    if pruned:
        audit.record("REALTIME_PRUNED", detail={"jobs": pruned, "keep_days": REALTIME_KEEP_DAYS})
        log.info("pruned old real-time scan records", extra={"ctx": {"jobs": pruned}})

    verdicts = VerdictRepository(db)
    intel_store = IntelStore(db)
    rule_store = RuleSetStore(db, paths.yara_rules_dir)
    level = privilege if privilege is not None else detect_privilege()
    engine_list = list(engines) if engines is not None else build_engines(config, paths, intel_store, rule_store)
    virustotal = VirusTotalService(config, store, audit, SecretFile(paths.root / "virustotal.key"))
    vt_client = VtClient(virustotal.key, quota_file=paths.root / "virustotal_quota.json")
    vt_engine = VirusTotalEngine(db, vt_client, virustotal.enabled)
    virustotal.attach(vt_client, vt_engine)
    if engines is None:
        engine_list.append(vt_engine)  # takes part only after consent and with a key (availability)
    yara_engine = next((e for e in engine_list if isinstance(e, YaraEngine)), None)

    # Was Sentinel X stopped, or its settings changed, while it was not looking? (audit 8, H4)
    self_check = SelfCheck(paths.root, paths.config_file, audit)
    store.on_saved = self_check.config_saved
    self_check.first_run = audit.last_detail("APP_START") is None
    self_check.start(utc_now_iso())

    audit.record(
        "APP_START",
        actor=AuditActor.SYSTEM,
        detail={"version": __version__, "privilege": level.value, "config_sha256": self_check.config_sha256},
    )
    log.info("bootstrap complete", extra={"ctx": {"root": str(paths.root), "privilege": level.value}})

    report_repo = ReportRepository(db)
    intel_service = IntelService(intel_store, rule_store, audit, yara_engine)
    scans = ScanService(engine_list, db, audit, config.scan, internal_root=paths.root,
                        internal_hashes=report_repo.hashes)
    vault = QuarantineVault(paths.vault_dir, db, audit, protected_root=paths.root)
    research = ResearchRepository(db)
    reports = ReportService(paths.reports_dir, report_repo, research, ScanRepository(db), audit,
                            scans.engine_statuses)
    quarantine = QuarantineService(vault, verdicts)
    return AppContainer(
        paths=paths,
        config_store=store,
        self_check=self_check,
        config=config,
        db=db,
        audit=audit,
        privilege=level,
        engines=engine_list,
        status=StatusService(paths.root, db, audit, level, engine_list),
        scans=scans,
        intel=intel_service,
        static=StaticAnalysisService(engine_list, audit, config.scan, verdicts.active_suppressions),
        reviews=ReviewService(verdicts, audit),
        quarantine=quarantine,
        monitor=MonitorService(paths, config, store, EventRepository(db), verdicts, audit, level),
        reports=reports,
        lab=LabService(config.scan, intel_store, research, audit, reports),
        settings=SettingsService(paths, store, config, audit),
        protection=ProtectionService(
            paths, config, store, engine_list, ScanRepository(db), ExclusionRepository(db), verdicts, quarantine, audit,
            clamd=build_clamd(config, paths), vault_dir=paths.vault_dir, own_change_age=vault.own_change_age,
            internal_hashes=report_repo.hashes),
        signatures=SignatureService(paths, config, store, audit, on_updated=_signatures_updated(engine_list),
                                    engine_ready=_clamav_ready(engine_list)),
        virustotal=virustotal,
        rule_updates=RuleUpdateService(config, store, audit, intel_service),
        sandbox=SandboxService(Sandbox(), engine_list, ScanRepository(db), verdicts, config.scan, audit),
    )
