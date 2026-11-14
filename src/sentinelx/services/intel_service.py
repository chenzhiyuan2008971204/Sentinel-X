"""Threat Intelligence use cases: hash intel sources and YARA rule sets."""

from __future__ import annotations

from pathlib import Path

from sentinelx.core.enums import AuditActor, ExclusionKind, IntelVerdict, TrustLevel
from sentinelx.engines.yara_engine import YaraEngine
from sentinelx.scanner.exclusions import validate_exclusion
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.intel_repository import ImportResult, IntelMatch, IntelStore, SourceRow
from sentinelx.storage.rules_repository import RuleSetRow, RuleSetStore


class IntelService:
    def __init__(self, intel: IntelStore, rules: RuleSetStore, audit: AuditLog, yara: YaraEngine | None) -> None:
        self._intel = intel
        self._rules = rules
        self._audit = audit
        self._yara = yara

    # ---- hash intel ----
    def sources(self) -> list[SourceRow]:
        return self._intel.sources()

    def import_hashes(self, path: Path, name: str, trust: TrustLevel,
                      default_verdict: IntelVerdict = IntelVerdict.MALICIOUS) -> ImportResult:
        res = self._intel.import_file(path, source_name=name, trust=trust, default_verdict=default_verdict)
        self._audit.record("INTEL_IMPORT", actor=AuditActor.USER, subject=name,
                           detail={"file": str(path), "trust": trust.value, "imported": res.imported,
                                   "invalid": res.invalid_count})
        return res

    def remove_source(self, source_id: int) -> bool:
        row = self._intel.remove_source(source_id)
        if row is None:
            return False
        self._audit.record("INTEL_REMOVE", actor=AuditActor.USER, subject=row.name)
        return True

    def lookup(self, sha256: str) -> list[IntelMatch]:
        h = validate_exclusion(ExclusionKind.SHA256, sha256)  # same validation rules for a hash
        return self._intel.lookup_many([h])[h]

    # ---- YARA ----
    def rule_sets(self) -> list[RuleSetRow]:
        return self._rules.list()

    def add_rule_file(self, path: Path, name: str | None = None, version: str | None = None) -> RuleSetRow:
        row = self._rules.add_from_file(path, name, version)
        self._audit.record("YARA_ADD", actor=AuditActor.USER, subject=row.name,
                           detail={"file": str(path), "version": row.version, "sha256": row.sha256,
                                   "valid": row.valid, "error": row.validation_error})
        self._reload()
        return row

    def set_rule_enabled(self, rule_set_id: int, enabled: bool) -> RuleSetRow:
        row = self._rules.set_enabled(rule_set_id, enabled)
        self._audit.record("YARA_ENABLE" if enabled else "YARA_DISABLE", actor=AuditActor.USER, subject=row.name)
        self._reload()
        return row

    def remove_rule_set(self, rule_set_id: int) -> bool:
        row = self._rules.remove(rule_set_id)
        if row is None:
            return False
        self._audit.record("YARA_REMOVE", actor=AuditActor.USER, subject=row.name)
        self._reload()
        return True

    def _reload(self) -> None:
        if self._yara is not None:
            self._yara.availability(refresh=True)
