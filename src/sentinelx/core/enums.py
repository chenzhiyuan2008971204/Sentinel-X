"""Enumerations shared across layers. Values are the strings persisted in SQLite and JSON."""

from __future__ import annotations

from enum import StrEnum


class Classification(StrEnum):
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    CONFIRMED_THREAT = "CONFIRMED_THREAT"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ScanStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"  # finished, but some files could not be fully assessed
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class EngineOutcomeKind(StrEnum):
    FINDINGS = "FINDINGS"
    NO_FINDINGS = "NO_FINDINGS"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"  # engine not applicable to this file type


class IntelVerdict(StrEnum):
    """Category of a hash in local threat intelligence."""

    MALICIOUS = "MALICIOUS"
    KNOWN_GOOD = "KNOWN_GOOD"


class TrustLevel(StrEnum):
    HIGH = "HIGH"  # curated / vetted source
    MEDIUM = "MEDIUM"
    LOW = "LOW"  # unvetted list


class SignatureStatus(StrEnum):
    VALID = "VALID"
    UNSIGNED = "UNSIGNED"
    INVALID = "INVALID"  # signature present but fails verification
    UNTRUSTED_ROOT = "UNTRUSTED_ROOT"
    UNKNOWN = "UNKNOWN"  # could not be determined


class ReviewDecision(StrEnum):
    CONFIRM = "CONFIRM"
    DISMISS_FALSE_POSITIVE = "DISMISS_FALSE_POSITIVE"
    ESCALATE = "ESCALATE"


class ExclusionKind(StrEnum):
    PATH = "PATH"
    PATH_PREFIX = "PATH_PREFIX"
    EXTENSION = "EXTENSION"
    SHA256 = "SHA256"


class QuarantineStatus(StrEnum):
    QUARANTINED = "QUARANTINED"
    RESTORED = "RESTORED"
    RETAINED_ERROR = "RETAINED_ERROR"
    DELETED = "DELETED"  # permanently deleted from the vault by the user (never automatic)


class EventSource(StrEnum):
    SYSMON = "SYSMON"
    EVENTLOG = "EVENTLOG"  # Windows Security log (4688) and Defender operational log
    PSUTIL = "PSUTIL"
    FSWATCH = "FSWATCH"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED = "DISMISSED"


class ReportKind(StrEnum):
    JSON = "JSON"
    HTML = "HTML"
    PDF = "PDF"


class AuditActor(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"


class PrivilegeLevel(StrEnum):
    STANDARD = "STANDARD"
    ADMINISTRATOR = "ADMINISTRATOR"
    UNKNOWN = "UNKNOWN"
