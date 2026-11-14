"""Domain data models shared by engines, the scanner and services."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.timeutil import utc_now_iso


@dataclass(frozen=True)
class EngineStatus:
    name: str
    available: bool
    version: str | None = None
    rules_version: str | None = None  # e.g. ClamAV signature DB version
    rules_date: str | None = None
    detail: str = ""  # why unavailable, or extra info (zh-TW, shown to the user)
    # True if this engine, in its current state, can actually detect malicious content.
    # Context engines (PE structure, hash intel with no malicious entries) are False:
    # they add evidence but a scan made only of them must not look like a completed scan.
    detection_capable: bool = True


@dataclass(frozen=True)
class ScanTarget:
    """A file that passed walking, limits and hashing, ready for engines."""

    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class DetectionRecord:
    """Structured evidence for one engine hit (CLAUDE.md §4)."""

    engine_name: str
    engine_version: str | None
    rule_id: str
    severity_hint: Severity
    evidence: dict[str, Any]
    file_sha256: str
    confidence_explanation: str
    timestamp: str = field(default_factory=utc_now_iso)


@dataclass(frozen=True)
class DetectionResult:
    """The standardized result every engine returns for one file.

    kind:
      FINDINGS     - one or more `detections` (structured evidence).
      NO_FINDINGS  - the engine fully assessed the file and found nothing.
      SKIPPED      - the engine does not apply to this file type (e.g. PE analysis on a
                     text file). Counts as completed; it is not a failure.
      ERROR        - the engine could not assess the file; `error` says why. Never clean.

    `info` holds non-detection facts the engine observed (PE metadata, hash reputation
    "unknown" vs "known good", signature status). Facts, not verdicts.
    """

    engine_name: str
    kind: EngineOutcomeKind
    engine_version: str | None = None
    rules_version: str | None = None
    detections: tuple[DetectionRecord, ...] = ()
    error: str | None = None
    duration_ms: int | None = None
    info: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def completed(self) -> bool:
        """True when the engine finished with the file (including 'not applicable')."""
        return self.kind is not EngineOutcomeKind.ERROR


@dataclass(frozen=True)
class FileResult:
    path: Path
    size: int | None
    mtime: str | None
    ctime: str | None
    sha256: str | None
    outcomes: tuple[DetectionResult, ...] = ()
    not_assessed_reason: str | None = None
    excluded: bool = False  # skipped by a user exclusion (a choice, not a failure)

    @property
    def assessed(self) -> bool:
        """Fully assessed = at least one engine ran and every engine completed."""
        return (
            self.not_assessed_reason is None
            and bool(self.outcomes)
            and all(o.completed for o in self.outcomes)
        )

    @property
    def detections(self) -> tuple[DetectionRecord, ...]:
        return tuple(d for o in self.outcomes for d in o.detections)


@dataclass
class ScanProgress:
    files_seen: int = 0
    files_done: int = 0
    files_skipped: int = 0
    detections: int = 0
    current_path: str = ""


@dataclass(frozen=True)
class ScanSummary:
    job_id: int
    status: str
    files_seen: int
    files_assessed: int
    files_not_assessed: int
    files_with_detections: int
    error_summary: str | None = None
    confirmed: int = 0
    suspicious: int = 0
    unknown: int = 0
    clean: int = 0
