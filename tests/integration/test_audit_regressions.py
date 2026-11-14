"""Regression tests for defects found in the Phase 3 engineering audit (ENGINEERING_AUDIT.md).

Each test is named after its finding id and failed before the fix.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import FakeEngine
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import IntelVerdict, ScanStatus, TrustLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.hash_intel import HashIntelEngine
from sentinelx.engines.pe_static import PEStaticEngine
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.orchestrator import ScanOrchestrator
from sentinelx.scanner.walker import Walker
from sentinelx.storage.db import Database
from sentinelx.storage.intel_repository import IntelStore
from sentinelx.storage.orm import ScanJob
from sentinelx.storage.rules_repository import validate_rule_source
from sentinelx.storage.scan_repository import ScanRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


def _scan(db: Database, engines: list, root: Path):  # type: ignore[no-untyped-def]
    return ScanOrchestrator(engines, ScanRepository(db), ScanLimits()).run([root], ExclusionSet(), CancelToken())


# ---- A1: context-only engines must not produce a "completed / nothing found" scan ----
def test_A1_context_only_engines_cannot_complete_a_scan(db: Database, tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("hello")
    s = _scan(db, [HashIntelEngine(IntelStore(db)), PEStaticEngine()], tmp_path)
    assert s.status == ScanStatus.FAILED.value
    assert "偵測引擎" in (s.error_summary or "")


def test_A1_hash_intel_with_malicious_entries_counts_as_detection(db: Database, tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("hello")
    lst = tmp_path.parent / f"{tmp_path.name}-list.txt"
    lst.write_text("a" * 64, encoding="utf-8")
    store = IntelStore(db)
    store.import_file(lst, source_name="S", trust=TrustLevel.HIGH)
    s = _scan(db, [HashIntelEngine(store), PEStaticEngine()], tmp_path)
    assert s.status == ScanStatus.COMPLETED.value


def test_A1_known_good_only_intel_is_not_detection_capable(db: Database, tmp_path: Path) -> None:
    lst = tmp_path / "good.txt"
    lst.write_text("a" * 64, encoding="utf-8")
    store = IntelStore(db)
    store.import_file(lst, source_name="G", trust=TrustLevel.HIGH, default_verdict=IntelVerdict.KNOWN_GOOD)
    assert not HashIntelEngine(store).availability().detection_capable


def test_A1_scan_service_gate_matches_orchestrator(make_container: MakeContainer) -> None:
    c = make_container([PEStaticEngine()])
    assert not c.scans.any_engine_available()


# ---- A2: jobs left RUNNING by a crash are closed at startup ----
def test_A2_interrupted_jobs_marked_failed(db: Database) -> None:
    repo = ScanRepository(db)
    job = repo.create_job(["C:\\x"], {})
    assert repo.mark_interrupted_jobs() == 1
    with db.session() as s:
        j = s.get(ScanJob, job)
        assert j.status == ScanStatus.FAILED.value and "未正常結束" in (j.error_summary or "")


# ---- A3: closing during a long engine call must not leave a running QThread ----
@pytest.mark.gui
def test_A3_static_analysis_can_be_cancelled_on_shutdown(qtbot: QtBot, make_container: MakeContainer,
                                                          tmp_path: Path) -> None:
    from sentinelx.gui.static_page import StaticAnalysisPage

    f = tmp_path / "f.txt"
    f.write_text("x")
    eng = FakeEngine(delay_per_file_s=60)
    p = StaticAnalysisPage(make_container([eng]).static)
    qtbot.addWidget(p)
    p.path_edit.setText(str(f))
    p.start_analysis()
    assert eng.started.wait(10)
    p.shutdown()
    assert not p.busy


# ---- A4: untrusted text must never be interpreted as rich text ----
@pytest.mark.gui
@pytest.mark.security
def test_A4_labels_showing_untrusted_text_are_plain(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    from sentinelx.gui.intel_page import ThreatIntelPage
    from sentinelx.gui.pages import DashboardPage
    from sentinelx.gui.scan_page import ScanCenterPage
    from sentinelx.gui.static_page import StaticAnalysisPage

    lst = tmp_path / "l.txt"
    lst.write_text(f"{'a' * 64},<b>bold</b><img src='x'>\n", encoding="utf-8")
    intel = ThreatIntelPage(container.intel)
    qtbot.addWidget(intel)
    intel.src_name.setText("<i>src</i>")
    intel.import_hashes(lst)
    qtbot.waitUntil(lambda: not intel.importing, timeout=30000)  # background import since Audit 4 (D2)
    intel.lookup_edit.setText("a" * 64)
    intel.lookup()
    scan = ScanCenterPage(container.scans)
    dash = DashboardPage(container.status)
    static = StaticAnalysisPage(container.static)
    for w in (intel, scan, dash, static):
        qtbot.addWidget(w)
    labels = [intel.lookup_result, intel.hash_msg, intel.rule_msg, scan.progress_label, scan.result_label,
              scan.excl_error, static.status_label, *(c.value for c in dash.cards.values())]
    for lbl in labels:
        assert lbl.textFormat() == Qt.TextFormat.PlainText, lbl.objectName() or lbl.text()
    assert "<b>bold</b>" in intel.lookup_result.text()  # shown literally


# ---- A5: module allow-list cannot be bypassed by placing the import mid-line ----
@pytest.mark.security
@pytest.mark.parametrize("src", [
    'rule a { condition: true } import "console"',
    'import "pe" import "console"\nrule a { condition: true }',
])
def test_A5_disallowed_module_anywhere_rejected(src: str) -> None:
    v = validate_rule_source(src)
    assert not v.ok and "console" in (v.error or "")


# ---- A6: an unreadable scan root is a per-path skip, not a failed job ----
def test_A6_root_stat_error_is_skip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "r"
    root.mkdir()
    real_stat = os.stat

    def flaky_stat(p, *a, **k):  # type: ignore[no-untyped-def]
        if os.fspath(p) == str(root):
            raise PermissionError(13, "Access is denied")
        return real_stat(p, *a, **k)

    monkeypatch.setattr(os, "stat", flaky_stat)
    [e] = list(Walker(ScanLimits()).walk([root], CancelToken()))
    assert not e.is_file and "權限不足" in (e.skip_reason or "")


# ---- A7: ClamAV default location follows %ProgramFiles% ----
def test_A7_clamav_location_uses_programfiles(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from sentinelx.engines import clamav

    pf = tmp_path / "PF"
    (pf / "ClamAV").mkdir(parents=True)
    (pf / "ClamAV" / "clamscan.exe").write_bytes(b"MZ")
    monkeypatch.setenv("ProgramFiles", str(pf))
    assert clamav.locate_clamscan() == pf / "ClamAV" / "clamscan.exe"
