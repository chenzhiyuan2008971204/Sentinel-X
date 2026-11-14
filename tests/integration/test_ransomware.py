"""0.16.0: ransomware warning (pattern of user files being encrypted), decoys, stopping a writer.

Only harmless synthetic file events and decoy files in a temporary folder are used."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

import psutil
import pytest
from fakes import FakeEngine

from sentinelx.app.bootstrap import AppContainer
from sentinelx.engines.base import DetectionEngine
from sentinelx.protection.ransomware import (
    DECOY_DIR,
    Decoys,
    RansomwareDetector,
    WriteSampler,
    _odd_copy_of_doc,
    stop_process,
)
from sentinelx.services.protection_service import ProtectionService
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def detector(root: Path, clock: Clock, writers: list[tuple[int, str, str, int]] | None = None,
             **kw: object) -> RansomwareDetector:
    procs = writers if writers is not None else []
    return RansomwareDetector(lambda: [root], clock=clock, sampler=WriteSampler(lambda: list(procs)), **kw)  # type: ignore[arg-type]


def test_odd_copy_names() -> None:
    assert _odd_copy_of_doc("report.docx.locked")
    assert _odd_copy_of_doc("photo.jpg.[id-1234].crypt")
    assert not _odd_copy_of_doc("report.docx")
    assert not _odd_copy_of_doc("report.docx.tmp")  # editors save through temp names
    assert not _odd_copy_of_doc("setup.exe")


def test_mass_rename_to_odd_extension_alerts_once(tmp_path: Path) -> None:
    clock = Clock()
    d = detector(tmp_path, clock)
    alerts = []
    for i in range(12):
        src = str(tmp_path / f"doc{i}.docx")
        a = d.event("moved", src, src + ".locked")
        clock.t += 0.5
        if a:
            alerts.append(a)
    assert len(alerts) == 1 and alerts[0].level == "bad" and "奇怪的副檔名" in alerts[0].reason
    assert d.alert is alerts[0]
    for i in range(12, 30):  # within the 10-minute cool-down: no repeated pop-ups
        src = str(tmp_path / f"doc{i}.docx")
        assert d.event("moved", src, src + ".locked") is None


def test_encrypt_copy_then_delete_alerts(tmp_path: Path) -> None:
    clock = Clock()
    d = detector(tmp_path, clock)
    got = None
    for i in range(11):
        doc = str(tmp_path / f"p{i}.jpg")
        got = d.event("created", doc + ".enc") or got
        got = d.event("deleted", doc) or got
    assert got is not None and got.level == "bad" and "刪除" in got.reason


def test_ordinary_activity_does_not_alert(tmp_path: Path) -> None:
    clock = Clock()
    d = detector(tmp_path, clock)
    for i in range(60):  # saving, editors' temp files, downloads, renames that keep a document type
        p = str(tmp_path / f"a{i}.docx")
        assert d.event("modified", p) is None
        assert d.event("created", p + ".tmp") is None
        assert d.event("moved", p, str(tmp_path / f"b{i}.docx")) is None
        assert d.event("created", str(tmp_path / f"setup{i}.exe")) is None
    outside = tmp_path.parent / "elsewhere"
    for i in range(50):  # outside the user's folders: not counted
        assert d.event("moved", str(outside / f"d{i}.docx"), str(outside / f"d{i}.docx.locked")) is None


def test_slow_changes_stay_below_the_window(tmp_path: Path) -> None:
    clock = Clock()
    d = detector(tmp_path, clock)
    for i in range(40):
        src = str(tmp_path / f"doc{i}.docx")
        assert d.event("moved", src, src + ".locked") is None
        clock.t += 3  # one file every 3 s never reaches 10 in 20 s (stated limit)


def test_many_modifications_is_only_a_warning(tmp_path: Path) -> None:
    clock = Clock()
    d = detector(tmp_path, clock)
    got = None
    for i in range(160):
        got = d.event("modified", str(tmp_path / f"m{i}.xlsx")) or got
    assert got is not None and got.level == "warn"


def test_top_writers_are_named(tmp_path: Path) -> None:
    clock = Clock()
    procs = [(4242, "lockerx.exe", r"C:\Users\u\AppData\lockerx.exe", 0), (7, "System", "", 0),
             (99, "notepad.exe", r"C:\Windows\notepad.exe", 0)]
    d = detector(tmp_path, clock, procs)
    d.tick()
    procs[:] = [(4242, "lockerx.exe", r"C:\Users\u\AppData\lockerx.exe", 80 * 1024 * 1024),
                (7, "System", "", 900 * 1024 * 1024), (99, "notepad.exe", r"C:\Windows\notepad.exe", 1024)]
    got = None
    for i in range(10):
        src = str(tmp_path / f"d{i}.pdf")
        got = d.event("moved", src, src + ".xyz") or got
    assert got is not None
    assert [(w.pid, w.name, w.written_mb) for w in got.writers] == [(4242, "lockerx.exe", 80.0)]


def test_decoys_place_detect_and_remove(tmp_path: Path) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    decoys = Decoys(lambda: [root])
    made = decoys.place()
    assert len(made) == 4 and all(p.parent.name == DECOY_DIR for p in made)
    assert decoys.paths() == set()  # their own creation events are ignored for 15 s
    decoys.placed_at -= 20
    clock = Clock()
    d = detector(root, clock, decoys=decoys.paths, decoy_changed=decoys.changed)
    target = made[0]
    assert d.event("modified", str(target)) is None  # attribute-only change (e.g. OneDrive): content unchanged
    target.write_bytes(b"encrypted!")
    a = d.event("modified", str(target))
    assert a is not None and a.level == "bad" and "誘餌" in a.reason
    # user turns decoys off: only Sentinel X's unchanged decoys are removed; the changed one stays
    assert decoys.remove() == 3
    assert target.exists() and not made[1].exists()
    target.unlink()
    assert decoys.remove() == 0
    assert not (root / DECOY_DIR).exists()  # folder removed once empty


def test_stop_process_refuses_windows_and_wrong_process() -> None:
    with pytest.raises(PermissionError):
        stop_process(4, "System")
    with pytest.raises(PermissionError):
        stop_process(1234, "explorer.exe")
    me = psutil.Process(os.getpid())
    assert "已經結束" in stop_process(os.getpid(), "not-" + me.name())  # number reused by another program


def test_stop_process_stops_a_harmless_child(tmp_path: Path) -> None:
    import subprocess
    import sys

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        name = psutil.Process(child.pid).name()
        assert "已停止" in stop_process(child.pid, name)
        assert child.wait(10) is not None
    finally:
        if child.poll() is None:
            child.kill()


# ---------------- real-time protection ----------------
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


def test_protection_reports_and_audits_alert(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    watched = tmp_path / "Documents"
    watched.mkdir()
    clock = Clock()
    det = detector(watched, clock)
    decoys = Decoys(lambda: [watched])
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          folders=lambda: [("文件", watched)], registry=Reg(), ransomware=det, decoys=decoys)
    notes: list[tuple[str, str, str]] = []
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    s.start()
    try:
        for i in range(10):
            src = str(watched / f"d{i}.docx")
            s._file_event("moved", src, src + ".locked")
        assert notes and notes[-1][0] == "bad" and "勒索病毒" in notes[-1][1]
        assert any(a.result == "勒索病毒警報" for a in s.activity())
        from sqlalchemy import text

        with c.db.engine.connect() as con:
            assert "RANSOMWARE_ALERT" in {a for (a,) in con.execute(text("SELECT action FROM audit_log"))}
        s.dismiss_ransomware_alert()
        assert det.alert is None
        # decoys are placed only after the user turns them on, and removed when turned off
        assert not (watched / DECOY_DIR).exists()
        s.update(ransomware_decoys=True)
        assert len(list((watched / DECOY_DIR).iterdir())) == 5  # 4 decoys + README
        s.update(ransomware_decoys=False)
        assert not (watched / DECOY_DIR).exists()
        s.update(ransomware_watch=False)
        for i in range(30):
            src = str(watched / f"e{i}.docx")
            s._file_event("moved", src, src + ".locked")
        assert len([n for n in notes if "勒索" in n[1]]) == 1
    finally:
        s.stop()


def test_real_file_events_reach_the_detector(make_container: MakeContainer, tmp_path: Path) -> None:
    """Real Windows file events: 12 harmless text files renamed like ransomware would."""
    import time

    c = make_container([FakeEngine()])
    watched = tmp_path / "Documents"
    watched.mkdir()
    files = []
    for i in range(12):
        f = watched / f"note{i}.txt"
        f.write_text("harmless test file", encoding="utf-8")
        files.append(f)
    det = RansomwareDetector(lambda: [watched], sampler=WriteSampler(lambda: []))
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          folders=lambda: [("文件", watched)], registry=Reg(), ransomware=det,
                          decoys=Decoys(lambda: [watched]))
    notes: list[tuple[str, str, str]] = []
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    s.start()
    try:
        time.sleep(0.5)
        for f in files:
            f.rename(f.with_name(f.name + ".locked"))
        end = time.monotonic() + 10
        while not any("勒索" in n[1] for n in notes) and time.monotonic() < end:
            time.sleep(0.1)
        assert any("勒索" in n[1] for n in notes)
    finally:
        s.stop()
