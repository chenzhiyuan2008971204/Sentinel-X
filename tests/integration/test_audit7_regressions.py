"""Audit 7 regression tests (real-time protection, 0.10.0). Harmless files only."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import psutil
import pytest
from fakes import MALWARE_MARKER, FakeEngine, SignatureAV
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ExclusionKind, PrivilegeLevel, ReportKind
from sentinelx.engines.base import DetectionEngine
from sentinelx.protection.process_guard import ProcessGuard
from sentinelx.reporting.document import new_document, table, tool_versions
from sentinelx.services.protection_service import ProtectionService
from sentinelx.storage.report_repository import ReportRepository
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
PING = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "PING.EXE"


class Reg:
    HKEY_CURRENT_USER, REG_SZ = 1, 1

    class K:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a) -> None:  # type: ignore[no-untyped-def]
            pass

    def CreateKey(self, *_a):  # type: ignore[no-untyped-def]  # noqa: N802
        return self.K()

    OpenKey = CreateKey  # noqa: N815

    def SetValueEx(self, *a) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        pass

    def DeleteValue(self, *a) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        pass


def service(c: AppContainer, folder: Path, drives: list[Path] | None = None) -> tuple[ProtectionService, list]:  # type: ignore[type-arg]
    notes: list = []  # type: ignore[type-arg]
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None,
                          removable=lambda: list(drives or []), folders=lambda: [("t", folder)], registry=Reg(),
                          internal_hashes=ReportRepository(c.db).hashes)  # as bootstrap wires it
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    return s, notes


def settle(s: ProtectionService, path: Path) -> None:
    s.notify_file(str(path))
    s.process_pending(time.monotonic() + 10)
    s.process_pending(time.monotonic() + 20)


# ---- G1: after protection was turned off mid-session, closing left an invisible process ----
@pytest.mark.gui
def test_G1_closing_really_quits(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QApplication

    from sentinelx.gui.main_window import MainWindow, Services

    c = make_container([])
    s, _ = service(c, tmp_path)
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor, c.reports,
                            c.lab, c.settings, c.signatures, s), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    quits: list[int] = []
    monkeypatch.setattr(QApplication, "quit", staticmethod(lambda: quits.append(1)))
    app = QApplication.instance()
    old = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)  # as main.py sets it when protection was on at start
    try:
        w.show()
        w.close()  # protection is off now: the window must end the application
        assert quits == [1]
    finally:
        app.setQuitOnLastWindowClosed(old)


# ---- G2: a process already running when its file is judged a threat was never re-checked ----
@pytest.mark.security
@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Windows processes")
def test_G2_guard_rechecks_running_processes_when_threats_change(tmp_path: Path) -> None:
    exe = tmp_path / "already-running.exe"
    shutil.copyfile(PING, exe)
    sha = hashlib.sha256(exe.read_bytes()).hexdigest()
    threats: set[str] = set()
    guard = ProcessGuard(lambda: set(threats), lambda _e: None, protected=lambda _p: False)
    code = "import subprocess, sys; subprocess.Popen([sys.argv[1], '-n', '60', '127.0.0.1'])"
    subprocess.run([sys.executable, "-c", code, str(exe)], check=True, timeout=60)
    proc = None
    for _ in range(100):
        proc = next((p for p in psutil.process_iter(["exe"])
                     if p.info["exe"] and os.path.normcase(p.info["exe"]) == os.path.normcase(str(exe))), None)
        if proc:
            break
        time.sleep(0.1)
    assert proc is not None
    try:
        assert guard.check_once() == []  # no threats known yet
        threats.add(sha)  # e.g. a copy of this file elsewhere was just judged CONFIRMED_THREAT
        killed = guard.check_once()
        assert [e.pid for e in killed if e.killed] == [proc.pid]
    finally:
        if proc.is_running():
            proc.kill()


# ---- G3: a removable-drive scan could not be cancelled and outlived stop() ----
class SlowEngine(FakeEngine):
    def scan_batch(self, targets, cancel):  # type: ignore[no-untyped-def]
        for _ in range(20):
            cancel.raise_if_cancelled()
            time.sleep(0.1)
        return super().scan_batch(targets, cancel)


def test_G3_drive_scan_cancelled_by_stop(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SlowEngine()])
    usb = tmp_path / "usb"
    usb.mkdir()
    for i in range(400):
        (usb / f"f{i}.txt").write_text(str(i))
    s, _ = service(c, tmp_path / "w", drives=[usb])
    (tmp_path / "w").mkdir()
    s.start()
    deadline = time.monotonic() + 10
    while not ScanRepository(c.db).list_jobs(include_realtime=True) and time.monotonic() < deadline:
        time.sleep(0.1)
    t = time.monotonic()
    s.stop()
    assert time.monotonic() - t < 5
    [job] = ScanRepository(c.db).list_jobs(include_realtime=True)
    assert job.status == "CANCELLED"


# ---- G5: own reports in watched folders were scanned (and could be quarantined); excluded files warned ----
def test_G5_exported_report_and_user_exclusions_are_left_alone(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    watched = tmp_path / "Documents"
    watched.mkdir()
    doc = new_document("SAMPLE", "t", "SAMPLE", "a" * 64, tool_versions(),
                       [table("YARA", ["片段"], [[MALWARE_MARKER.decode()]])], {"excerpt": MALWARE_MARKER.decode()})
    [row] = c.reports.generate(doc, [ReportKind.JSON]).rows
    exported = watched / "my-report.json"
    c.reports.export_copy(row, exported)
    excluded = watched / "lab-sample.bin"
    excluded.write_bytes(MALWARE_MARKER + b"x")
    c.scans.add_exclusion(ExclusionKind.PATH, str(excluded), "my lab sample")
    s, notes = service(c, watched)
    s.start()
    try:
        settle(s, exported)
        settle(s, excluded)
        assert exported.exists() and excluded.exists() and c.quarantine.items() == []
        assert notes == [] and s.activity() == []
        # a manual scan of the folder does not flag the exported report either
        summary = c.scans.run_scan([watched], CancelToken())
        assert summary.confirmed == 0 and summary.suspicious == 0
        assert row.sha256 in c.protection._internal_hashes()  # the app's own wiring includes reports
    finally:
        s.stop()

