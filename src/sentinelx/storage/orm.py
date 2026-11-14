"""SQLAlchemy ORM models. Mirrors DATABASE_SCHEMA.md; keep the two in sync."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sentinelx.core.enums import (
    AlertStatus,
    AuditActor,
    Classification,
    EngineOutcomeKind,
    EventSource,
    ExclusionKind,
    QuarantineStatus,
    ReportKind,
    ReviewDecision,
    ScanStatus,
    Severity,
)
from sentinelx.core.timeutil import utc_now_iso

SCHEMA_VERSION = 7

# Forward-only migrations: version -> SQL statements that bring version-1 up to it.
# A fresh database is created directly at SCHEMA_VERSION by create_all.
MIGRATIONS: dict[int, list[str]] = {
    2: ["ALTER TABLE engine_runs ADD COLUMN info_json TEXT NOT NULL DEFAULT '{}'"],
    3: [
        "ALTER TABLE verdicts ADD COLUMN confidence TEXT NOT NULL DEFAULT '—'",
        "ALTER TABLE verdicts ADD COLUMN needs_review INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE verdicts ADD COLUMN assessor_version TEXT",
        "CREATE TABLE IF NOT EXISTS fp_suppressions ("
        " id INTEGER PRIMARY KEY, sha256 VARCHAR(64) NOT NULL, rule_id TEXT, reason TEXT NOT NULL,"
        " created_at VARCHAR NOT NULL, active INTEGER NOT NULL DEFAULT 1, review_id INTEGER REFERENCES manual_reviews(id))",
        "CREATE INDEX IF NOT EXISTS ix_fp_sha256 ON fp_suppressions (sha256)",
    ],
    4: [
        "ALTER TABLE quarantine_items ADD COLUMN xor_key TEXT",
        "ALTER TABLE quarantine_items ADD COLUMN duplicate_of INTEGER REFERENCES quarantine_items(id)",
        "ALTER TABLE quarantine_items ADD COLUMN original_mtime TEXT",
        "ALTER TABLE quarantine_items ADD COLUMN original_attributes INTEGER",
        "ALTER TABLE quarantine_items ADD COLUMN reason TEXT",
        "ALTER TABLE quarantine_items ADD COLUMN restore_target TEXT",
        "ALTER TABLE quarantine_items ADD COLUMN audit_entry_id INTEGER REFERENCES audit_log(id)",
        "ALTER TABLE quarantine_items ADD COLUMN error_detail TEXT",
    ],
    5: [
        "ALTER TABLE security_events ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE alerts ADD COLUMN rule_id TEXT",
        "ALTER TABLE alerts ADD COLUMN dedup_key TEXT",
        "ALTER TABLE alerts ADD COLUMN updated_at TEXT",
        "CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts (dedup_key)",
        "CREATE INDEX IF NOT EXISTS ix_events_kind ON security_events (kind)",
    ],
}


def enum_check(column: str, enum: type[StrEnum], *, nullable: bool = False) -> CheckConstraint:
    values = ", ".join(f"'{e.value}'" for e in enum)
    expr = f"{column} IN ({values})"
    if nullable:
        expr = f"{column} IS NULL OR {expr}"
    return CheckConstraint(expr, name=f"ck_{column}_enum")


class Base(DeclarativeBase):
    pass


class SchemaMeta(Base):
    __tablename__ = "schema_meta"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (enum_check("status", ScanStatus),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    finished_at: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default=ScanStatus.RUNNING.value)
    targets_json: Mapped[str] = mapped_column(Text, default="[]")
    options_json: Mapped[str] = mapped_column(Text, default="{}")
    files_seen: Mapped[int] = mapped_column(Integer, default=0)
    files_assessed: Mapped[int] = mapped_column(Integer, default=0)
    files_not_assessed: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)


class FileRecord(Base):
    __tablename__ = "files"
    __table_args__ = (
        Index("ix_files_sha256", "sha256"),
        Index("ix_files_path_norm", "path_norm"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str | None] = mapped_column(String(64))  # NULL when the file could not be read
    size: Mapped[int | None] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(Text)
    path_norm: Mapped[str] = mapped_column(Text)
    mtime: Mapped[str | None] = mapped_column(String)
    ctime: Mapped[str | None] = mapped_column(String)
    first_seen_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String, default=utc_now_iso)


class Verdict(Base):
    __tablename__ = "verdicts"
    __table_args__ = (enum_check("classification", Classification),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("files.id"))
    classification: Mapped[str] = mapped_column(String)
    ordinal_score: Mapped[int] = mapped_column(Integer, default=0)
    explanation: Mapped[str] = mapped_column(Text)
    contributing_detection_ids: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    superseded_by: Mapped[int | None] = mapped_column(ForeignKey("verdicts.id"))
    confidence: Mapped[str] = mapped_column(Text, default="—", server_default="—")  # v3
    needs_review: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # v3
    assessor_version: Mapped[str | None] = mapped_column(Text)  # v3


class FpSuppression(Base):
    """User false-positive decision (v3). Detections stay stored; they are just not counted."""

    __tablename__ = "fp_suppressions"
    __table_args__ = (Index("ix_fp_sha256", "sha256"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str | None] = mapped_column(Text)  # NULL = every rule for this hash
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    active: Mapped[int] = mapped_column(Integer, default=1)
    review_id: Mapped[int | None] = mapped_column(ForeignKey("manual_reviews.id"))


class FileScan(Base):
    __tablename__ = "file_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    file_id: Mapped[int] = mapped_column(ForeignKey("files.id"))
    assessed: Mapped[int] = mapped_column(Integer, default=0)
    not_assessed_reason: Mapped[str | None] = mapped_column(Text)
    verdict_id: Mapped[int | None] = mapped_column(ForeignKey("verdicts.id"))


class EngineRun(Base):
    __tablename__ = "engine_runs"
    __table_args__ = (enum_check("outcome", EngineOutcomeKind),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_scan_id: Mapped[int] = mapped_column(ForeignKey("file_scans.id", ondelete="CASCADE"))
    engine_name: Mapped[str] = mapped_column(String)
    engine_version: Mapped[str | None] = mapped_column(String)
    rules_version: Mapped[str | None] = mapped_column(String)
    outcome: Mapped[str] = mapped_column(String)
    error_detail: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    info_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # v2


class Detection(Base):
    __tablename__ = "detections"
    __table_args__ = (enum_check("severity_hint", Severity),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engine_run_id: Mapped[int] = mapped_column(ForeignKey("engine_runs.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String)
    severity_hint: Mapped[str] = mapped_column(String)
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    confidence_explanation: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    file_sha256: Mapped[str] = mapped_column(String(64))


class ManualReview(Base):
    __tablename__ = "manual_reviews"
    __table_args__ = (enum_check("decision", ReviewDecision),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    verdict_id: Mapped[int] = mapped_column(ForeignKey("verdicts.id"))
    decision: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    reviewed_at: Mapped[str] = mapped_column(String, default=utc_now_iso)


class Exclusion(Base):
    __tablename__ = "exclusions"
    __table_args__ = (enum_check("kind", ExclusionKind),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    enabled: Mapped[int] = mapped_column(Integer, default=1)


class QuarantineItem(Base):
    __tablename__ = "quarantine_items"
    __table_args__ = (enum_check("status", QuarantineStatus),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vault_id: Mapped[str] = mapped_column(String, unique=True)
    original_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    verdict_id: Mapped[int | None] = mapped_column(ForeignKey("verdicts.id"))
    confirmed_by_user_at: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default=QuarantineStatus.QUARANTINED.value)
    restored_at: Mapped[str | None] = mapped_column(String)
    zone_identifier: Mapped[str | None] = mapped_column(Text)
    xor_key: Mapped[str | None] = mapped_column(Text)  # v4, hex; obfuscation, not a security control
    duplicate_of: Mapped[int | None] = mapped_column(ForeignKey("quarantine_items.id"))  # v4
    original_mtime: Mapped[str | None] = mapped_column(Text)  # v4
    original_attributes: Mapped[int | None] = mapped_column(Integer)  # v4
    reason: Mapped[str | None] = mapped_column(Text)  # v4
    restore_target: Mapped[str | None] = mapped_column(Text)  # v4
    audit_entry_id: Mapped[int | None] = mapped_column(ForeignKey("audit_log.id"))  # v4
    error_detail: Mapped[str | None] = mapped_column(Text)  # v4
    deleted_at: Mapped[str | None] = mapped_column(String)  # v6: permanently deleted by the user


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        enum_check("source", EventSource),
        Index("ix_events_time", "occurred_at"),
        Index("ix_events_sha256", "sha256"),
        Index("ix_events_process_path", "process_path"),
        Index("ix_events_kind", "kind"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    occurred_at: Mapped[str] = mapped_column(String)
    process_name: Mapped[str | None] = mapped_column(Text)
    process_path: Mapped[str | None] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    command_line: Mapped[str | None] = mapped_column(Text)
    target_path: Mapped[str | None] = mapped_column(Text)
    remote_addr: Mapped[str | None] = mapped_column(String)
    remote_port: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    raw_ref: Mapped[str | None] = mapped_column(Text)
    details_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # v5


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (enum_check("status", AlertStatus), enum_check("severity", Severity),
                      Index("ix_alerts_dedup", "dedup_key"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    title: Mapped[str] = mapped_column(Text)
    observed_facts: Mapped[str] = mapped_column(Text, default="[]")
    analytic_notes: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String)
    event_ids: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String, default=AlertStatus.OPEN.value)
    rule_id: Mapped[str | None] = mapped_column(Text)  # v5
    dedup_key: Mapped[str | None] = mapped_column(Text)  # v5
    updated_at: Mapped[str | None] = mapped_column(Text)  # v5


class IntelSource(Base):
    __tablename__ = "intel_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    imported_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    trust_level: Mapped[str] = mapped_column(String)
    origin_note: Mapped[str | None] = mapped_column(Text)


class IntelHash(Base):
    __tablename__ = "intel_hashes"
    __table_args__ = (UniqueConstraint("source_id", "sha256"), Index("ix_intel_sha256", "sha256"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("intel_sources.id", ondelete="CASCADE"))
    sha256: Mapped[str] = mapped_column(String(64))
    label: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String)
    added_at: Mapped[str] = mapped_column(String, default=utc_now_iso)


class RuleSet(Base):
    __tablename__ = "rule_sets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String, default="YARA")
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    path: Mapped[str] = mapped_column(Text)
    sha256_of_rules: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    validated_at: Mapped[str | None] = mapped_column(String)
    validation_error: Mapped[str | None] = mapped_column(Text)


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (enum_check("kind", ReportKind),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String)
    created_at: Mapped[str] = mapped_column(String, default=utc_now_iso)
    subject_type: Mapped[str] = mapped_column(String)
    subject_ref: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    tool_versions_json: Mapped[str] = mapped_column(Text, default="{}")


class AuditEntry(Base):
    __tablename__ = "audit_log"
    __table_args__ = (enum_check("actor", AuditActor),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[str] = mapped_column(String)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    subject: Mapped[str] = mapped_column(Text, default="")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class VtReport(Base):
    """v7: cached VirusTotal hash lookups (only the SHA-256 is ever sent)."""

    __tablename__ = "vt_reports"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    found: Mapped[int] = mapped_column(Integer)  # 0 = VirusTotal has never seen this file
    malicious: Mapped[int] = mapped_column(Integer, default=0)
    suspicious: Mapped[int] = mapped_column(Integer, default=0)
    engines_total: Mapped[int] = mapped_column(Integer, default=0)
    threat_label: Mapped[str | None] = mapped_column(Text)
    names_json: Mapped[str] = mapped_column(Text, default="[]")  # ["Engine: result", ...]
    sandbox_malicious: Mapped[int] = mapped_column(Integer, default=0)
    last_analysis: Mapped[str | None] = mapped_column(String)  # UTC, from VirusTotal
    fetched_at: Mapped[str] = mapped_column(String)


def _rebuild_quarantine_items() -> list[str]:
    """v6: SQLite cannot change a CHECK constraint, so the table is rebuilt with the new status
    value (DELETED) and the deleted_at column; all rows are copied unchanged."""
    from sqlalchemy.dialects import sqlite
    from sqlalchemy.schema import CreateTable

    create = str(CreateTable(QuarantineItem.__table__).compile(dialect=sqlite.dialect())).strip()
    create = create.replace("CREATE TABLE quarantine_items", "CREATE TABLE quarantine_items_v6", 1)
    old_cols = ", ".join(c.name for c in QuarantineItem.__table__.columns if c.name != "deleted_at")
    return [
        create,
        f"INSERT INTO quarantine_items_v6 ({old_cols}) SELECT {old_cols} FROM quarantine_items",
        "DROP TABLE quarantine_items",
        "ALTER TABLE quarantine_items_v6 RENAME TO quarantine_items",
    ]


MIGRATIONS[6] = _rebuild_quarantine_items()


def _create_if_missing(table) -> list[str]:  # type: ignore[no-untyped-def]
    from sqlalchemy.dialects import sqlite
    from sqlalchemy.schema import CreateTable

    return [str(CreateTable(table, if_not_exists=True).compile(dialect=sqlite.dialect())).strip()]


MIGRATIONS[7] = _create_if_missing(VtReport.__table__)
