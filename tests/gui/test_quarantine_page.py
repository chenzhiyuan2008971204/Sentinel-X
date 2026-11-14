from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.quarantine_page import QuarantinePage
from sentinelx.gui.threat_page import ThreatCenterPage

pytestmark = [pytest.mark.gui, pytest.mark.skipif(sys.platform != "win32", reason="vault uses Windows APIs")]
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


class Answer:
    def __init__(self, value: bool) -> None:
        self.value = value
        self.asked: list[str] = []

    def __call__(self, _parent, _title: str, message: str) -> bool:  # type: ignore[no-untyped-def]
        self.asked.append(message)
        return self.value


@pytest.fixture
def setup(make_container: MakeContainer, tmp_path: Path):  # type: ignore[no-untyped-def]
    c = make_container([SignatureAV()])
    f = tmp_path / "evil.bin"
    f.write_bytes(MALWARE_MARKER)
    c.scans.run_scan([f], CancelToken())
    return c, f


def idle(qtbot: QtBot, page) -> None:  # type: ignore[no-untyped-def]
    """Quarantine, restore and verify run in the background since Phase 8."""
    qtbot.waitUntil(lambda: not page.busy, timeout=30000)


def threat_page(qtbot: QtBot, c: AppContainer, answer: Answer) -> ThreatCenterPage:
    p = ThreatCenterPage(c.reviews, c.quarantine, confirm=answer)
    qtbot.addWidget(p)
    p.show()
    p.table.selectRow(0)
    return p


def test_quarantine_from_threat_center_needs_reason_and_confirmation(qtbot: QtBot, setup) -> None:  # type: ignore[no-untyped-def]
    c, f = setup
    no = Answer(False)
    p = threat_page(qtbot, c, no)
    assert p.quarantine_button.isEnabled()

    qtbot.mouseClick(p.quarantine_button, Qt.MouseButton.LeftButton)
    assert "原因" in p.msg.text() and no.asked == [] and f.exists()

    p.reason_edit.setText("確認惡意")
    qtbot.mouseClick(p.quarantine_button, Qt.MouseButton.LeftButton)
    assert no.asked and str(f) in no.asked[0] and "已取消" in p.msg.text() and f.exists()

    p.confirm = Answer(True)
    qtbot.mouseClick(p.quarantine_button, Qt.MouseButton.LeftButton)
    assert p.busy and not p.busy_bar.isHidden() and p.busy_bar.cancel_button.isHidden()  # not cancellable
    assert not p.quarantine_button.isEnabled() and not p.confirm_button.isEnabled()
    idle(qtbot, p)
    assert p.busy_bar.isHidden()
    assert not f.exists() and "已隔離" in p.msg.text()
    assert "已隔離" in p.table.item(0, 4).text()
    assert not p.quarantine_button.isEnabled()  # already quarantined


def test_restore_from_quarantine_page(qtbot: QtBot, setup) -> None:  # type: ignore[no-untyped-def]
    c, f = setup
    tp = threat_page(qtbot, c, Answer(True))
    tp.reason_edit.setText("r")
    tp.quarantine_selected()
    idle(qtbot, tp)
    assert not f.exists()

    no = Answer(False)
    qp = QuarantinePage(c.quarantine, confirm=no)
    qtbot.addWidget(qp)
    assert "正常" in qp.vault_status.text() and qp.table.rowCount() == 1
    assert not qp.restore_button.isEnabled()
    qp.table.selectRow(0)
    assert qp.restore_button.isEnabled()

    qtbot.mouseClick(qp.verify_button, Qt.MouseButton.LeftButton)
    assert qp.busy and not qp.verify_button.isEnabled()
    idle(qtbot, qp)
    assert "通過" in qp.msg.text()

    qtbot.mouseClick(qp.restore_button, Qt.MouseButton.LeftButton)
    assert "已取消" in qp.msg.text() and not f.exists()
    assert str(f) in no.asked[0] and "SHA-256" in no.asked[0]

    qp.confirm = Answer(True)
    qp.table.selectRow(0)
    qtbot.mouseClick(qp.restore_button, Qt.MouseButton.LeftButton)
    idle(qtbot, qp)
    assert f.read_bytes() == MALWARE_MARKER and "驗證相符" in qp.msg.text()
    assert qp.table.item(0, 1).text() == "已還原"
    qp.table.selectRow(0)
    assert not qp.restore_button.isEnabled()


def test_only_one_delete_button_and_it_asks_first(qtbot: QtBot, setup) -> None:  # type: ignore[no-untyped-def]
    """0.14.0: the user asked for permanent delete. Exactly one button, disabled without a
    selection, and it never deletes without a "yes" (see test_quarantine.py for the rest)."""
    c, _ = setup
    asked: list[str] = []
    qp = QuarantinePage(c.quarantine, confirm=lambda _p, title, _m: asked.append(title) or False)
    qtbot.addWidget(qp)
    from PySide6.QtWidgets import QPushButton

    labels = [b.text() for b in qp.findChildren(QPushButton)]
    assert [t for t in labels if "刪除" in t or "清除" in t] == ["永久刪除…"]
    assert not qp.delete_button.isEnabled()  # nothing selected


@pytest.mark.parametrize("mark", [True, False])
def test_restore_asks_whether_to_mark_safe(qtbot: QtBot, setup, mark: bool) -> None:  # type: ignore[no-untyped-def]
    """2026-11-09: restoring alone does not trust the file; the page asks, and "yes" marks the
    whole file as a false positive so the same download is not blocked again."""
    c, f = setup
    vid = next(t.verdict_id for t in c.reviews.threats())
    c.quarantine.quarantine_verdict(vid, "r", confirmed=True)
    answers = [True, mark]  # restore? then: also mark as false positive?
    asked: list[str] = []

    def confirm(_p, title: str, _m: str) -> bool:  # type: ignore[no-untyped-def]
        asked.append(title)
        return answers.pop(0)

    qp = QuarantinePage(c.quarantine, confirm=confirm, mark_safe=c.reviews.dismiss_whole_file)
    qtbot.addWidget(qp)
    qp.table.selectRow(0)
    qp.restore_selected(None)
    idle(qtbot, qp)
    assert f.read_bytes() == MALWARE_MARKER and len(asked) == 2 and "誤判" in asked[1]
    whole_file = [s for s in c.reviews.suppressions() if s.rule_id is None]
    if mark:
        assert len(whole_file) == 1 and "之後不會再被擋" in qp.msg.text() and not c.reviews.threats()
    else:
        assert not whole_file and "之後不會再被擋" not in qp.msg.text() and c.reviews.threats()
