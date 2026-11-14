"""Phase 9 QA finding: showing a finished scan froze the window (4.2 s for 1 500 files) because
job_files() ran several queries per file. Now a fixed number of queries and a display cap."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from pytestqt.qtbot import QtBot
from sqlalchemy import event

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.pe_static import PEStaticEngine
from sentinelx.gui import scan_page as sp

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


def _scan(c: AppContainer, root: Path, n: int) -> int:
    root.mkdir()
    for i in range(n):
        (root / f"f{i:03d}.bin").write_bytes((MALWARE_MARKER if i == n - 1 else b"ok") + bytes([i % 256]))
    return c.scans.run_scan([root], CancelToken()).job_id


def test_job_files_query_count_does_not_grow(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV(), PEStaticEngine()])
    small, big = _scan(c, tmp_path / "a", 5), _scan(c, tmp_path / "b", 120)
    counts = []
    for job in (small, big):
        n = [0]

        def count(*_a, n=n):  # type: ignore[no-untyped-def]
            n[0] += 1

        event.listen(c.db.engine, "before_cursor_execute", count)
        rows = c.scans.job_files(job)
        event.remove(c.db.engine, "before_cursor_execute", count)
        counts.append(n[0])
        assert sum(1 for r in rows if r.detections) == 1
    assert counts[0] == counts[1] <= 5, counts


def test_files_table_capped_with_findings_first(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    c = make_container([SignatureAV()])
    _scan(c, tmp_path / "s", 8)
    monkeypatch.setattr(sp, "MAX_FILE_ROWS", 3)
    page = sp.ScanCenterPage(c.scans)
    qtbot.addWidget(page)
    page.refresh_history()
    page.jobs_table.selectRow(0)
    page._show_selected_job()
    assert page.files_table.rowCount() == 3
    assert "f007.bin" in page.files_table.item(0, 1).text()  # the detection is shown first
    assert "共 8 個檔案" in page.files_note.text() and "掃描報告" in page.files_note.text()
