"""Audit 3 regression tests (after Phase 7). One test per confirmed defect, written before the fix."""

from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
import pytest
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import EventSource, ReportKind
from sentinelx.monitor import wevt
from sentinelx.monitor.collectors import CollectorStatus, ProcessCollector
from sentinelx.monitor.correlation import Correlator, ThreatIndex
from sentinelx.monitor.runner import MonitorRunner
from sentinelx.reporting.document import new_document, table, tool_versions
from sentinelx.services.report_service import Integrity

pytestmark = pytest.mark.integration
ALL = [ReportKind.JSON, ReportKind.HTML, ReportKind.PDF]


def _doc(cell: str) -> dict:  # type: ignore[type-arg]
    return new_document("SAMPLE", "t", "SAMPLE", "a" * 64, tool_versions(), [table("big", ["a", "b"], [[cell, 1]])], {})


# ---- C1: a very long table cell made ReportLab raise LayoutError out of generate() ----
@pytest.mark.parametrize("columns", [2, 10])
def test_C1_long_cell_does_not_abort_reports(container: AppContainer, columns: int) -> None:
    long = "長" * 30_000
    doc = new_document("SAMPLE", "t", "SAMPLE", "a" * 64, tool_versions(),
                       [table("big", [f"c{i}" for i in range(columns)], [[long] * columns]),
                        {"type": "fields", "title": "f", "rows": [["k", long]]},
                        {"type": "text", "title": "p", "paragraphs": [long]}], {})
    res = container.reports.generate(doc, ALL)
    assert [r.kind for r in res.rows] == ALL and not res.errors
    import pypdf

    text = "".join(p.extract_text() or "" for p in pypdf.PdfReader(res.rows[2].path).pages)
    assert "完整內容見 JSON" in text


def test_C1_unexpected_writer_error_is_reported_not_raised(container: AppContainer,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_doc):  # type: ignore[no-untyped-def]
        raise RuntimeError("writer bug")

    monkeypatch.setattr("sentinelx.services.report_service.to_html", boom)
    res = container.reports.generate(_doc("x"), ALL)
    assert [r.kind for r in res.rows] == [ReportKind.JSON, ReportKind.PDF]
    assert len(res.errors) == 1 and "RuntimeError" in res.errors[0]
    assert not [p for p in container.paths.reports_dir.iterdir() if p.name.startswith(".")]


# ---- C2: the Reports page hashed every report on the GUI thread ----
@pytest.mark.gui
def test_C2_integrity_checked_off_the_gui_thread(qtbot: QtBot, container: AppContainer,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelx.gui.reports_page import ReportsPage

    container.reports.generate(_doc("x"), [ReportKind.JSON, ReportKind.HTML])
    threads: list[str] = []
    real = container.reports.integrity

    def spy(row):  # type: ignore[no-untyped-def]
        threads.append(threading.current_thread().name)
        return real(row)

    monkeypatch.setattr(container.reports, "integrity", spy)
    p = ReportsPage(container.reports, confirm=lambda *a: False, opener=lambda _p: True)
    qtbot.addWidget(p)
    qtbot.waitUntil(lambda: not p.verifying, timeout=30000)
    assert threads and threading.main_thread().name not in threads
    assert set(p.integrity.values()) == {Integrity.OK}
    assert all(p.table.item(r, 5).text() == "未變更" for r in range(p.table.rowCount()))
    p.shutdown()


# ---- C3: export_copy checked the hash, then copied without checking what was copied ----
@pytest.mark.security
def test_C3_copy_verified_and_not_into_reports_dir(container: AppContainer, tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    [row] = container.reports.generate(_doc("x"), [ReportKind.JSON]).rows
    with pytest.raises(ValueError, match="報告資料夾"):
        container.reports.export_copy(row, container.paths.reports_dir / "other.json")

    def swapped_copy(src, dst):  # type: ignore[no-untyped-def]
        Path(dst).write_text("changed during copy", encoding="utf-8")

    monkeypatch.setattr(shutil, "copyfile", swapped_copy)
    dest = tmp_path / "c.json"
    with pytest.raises(ValueError, match="不符"):
        container.reports.export_copy(row, dest)
    assert not dest.exists()


# ---- C4: one unrenderable event leaked handles and blocked the whole channel ----
class _FakeEvt:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.calls = 0

    def EvtQuery(self, *a):  # type: ignore[no-untyped-def]  # noqa: N802
        return 999

    def EvtNext(self, q, want, arr, timeout, flags, returned):  # type: ignore[no-untyped-def]  # noqa: N802
        self.calls += 1
        if self.calls > 1:
            ctypes.set_last_error(wevt.ERROR_NO_MORE_ITEMS)
            return False
        for i in range(3):
            arr[i] = i + 1
        returned._obj.value = 3
        return True

    def EvtClose(self, h):  # type: ignore[no-untyped-def]  # noqa: N802
        self.closed.append(int(h))
        return True


def test_C4_bad_event_is_skipped_and_handles_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEvt()
    monkeypatch.setattr(wevt, "_api", fake)

    def render(h):  # type: ignore[no-untyped-def]
        if h == 2:
            raise wevt.EventLogError(13, "EvtRender")
        return f"<Event>{h}</Event>"

    monkeypatch.setattr(wevt, "_render", render)
    out = wevt.query_xml("X", "*")
    assert out == ["<Event>1</Event>", "<Event>3</Event>"]
    assert sorted(fake.closed) == [1, 2, 3, 999]


# ---- C5: AccessDenied while reading a new process's name dropped the whole poll ----
@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Windows process APIs")
def test_C5_access_denied_name_keeps_other_events(monkeypatch: pytest.MonkeyPatch) -> None:
    col = ProcessCollector(ignore_self=False)
    col.start()
    a = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    b = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.5)
        real = psutil.Process.name

        def name(self):  # type: ignore[no-untyped-def]
            if self.pid == a.pid:
                raise psutil.AccessDenied(self.pid)
            return real(self)

        monkeypatch.setattr(psutil.Process, "name", name)
        events = {e.pid: e for e in col.poll()}
        assert b.pid in events and a.pid in events
        assert events[a.pid].process_name is None and "name" in events[a.pid].details["access_denied"]
    finally:
        a.kill()
        b.kill()


# ---- C6: stop() after a join timeout stopped collectors under a still-running loop ----
class _BlockingCollector:
    name = "blocking"
    source = EventSource.PSUTIL

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.stopped = False

    def status(self) -> CollectorStatus:
        return CollectorStatus(self.name, self.source, True, "")

    def start(self) -> None:
        pass

    def poll(self):  # type: ignore[no-untyped-def]
        self.entered.set()
        self.release.wait(10)
        return []

    def stop(self) -> None:
        self.stopped = True


def test_C6_stop_timeout_keeps_runner_consistent(container: AppContainer) -> None:
    from sentinelx.storage.event_repository import EventRepository

    col = _BlockingCollector()
    r = MonitorRunner([col], EventRepository(container.db), Correlator(), ThreatIndex, interval_s=0.05)
    r.start()
    assert col.entered.wait(5)
    assert r.stop(timeout=0.2) is False
    assert r.running and not col.stopped  # loop still inside poll(): collectors untouched
    assert r.start() == r.statuses and r.running  # no second loop
    col.release.set()
    assert r.stop(timeout=5) is True
    assert not r.running and col.stopped
