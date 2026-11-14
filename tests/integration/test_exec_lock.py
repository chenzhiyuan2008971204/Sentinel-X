"""0.12.0: new programs in Downloads are locked (deny execute) until checked. Real Windows ACLs,
harmless copies of PING.EXE only; nothing unknown is ever executed."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, FakeEngine, SignatureAV
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import ExclusionKind
from sentinelx.engines.base import DetectionEngine
from sentinelx.protection import exec_lock
from sentinelx.protection.exec_lock import HELD, PENDING, LockEntry, LockRegistry, can_execute
from sentinelx.services.protection_service import ProtectionService
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = [pytest.mark.integration, pytest.mark.windows,
              pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")]
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
PING = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "PING.EXE"


class Reg:
    HKEY_CURRENT_USER = REG_SZ = 1

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


def service(c: AppContainer, downloads: Path) -> tuple[ProtectionService, list[tuple[str, str, str]]]:
    notes: list[tuple[str, str, str]] = []
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          folders=lambda: [("下載", downloads)], registry=Reg(), downloads=lambda: downloads)
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    return s, notes


def settle(s: ProtectionService, path: Path) -> None:
    s.notify_file(str(path))
    s.process_pending(time.monotonic() + 10)
    s.process_pending(time.monotonic() + 20)


def starts(path: Path) -> bool:
    """Try to start the harmless PING copy. False when Windows refuses (access denied)."""
    try:
        subprocess.run([str(path), "-n", "1", "127.0.0.1"], capture_output=True, timeout=30)
    except PermissionError:
        return False
    except OSError as exc:
        if getattr(exc, "winerror", None) == 5:
            return False
        raise
    return True


def actions(c: AppContainer) -> list[str]:
    with c.db.engine.connect() as con:
        return [a for (a,) in con.execute(text("SELECT action FROM audit_log"))]


@pytest.fixture
def downloads(tmp_path: Path) -> Path:
    d = tmp_path / "Downloads"
    d.mkdir()
    return d


def test_lock_and_unlock_primitives(tmp_path: Path) -> None:
    p = tmp_path / "p.exe"
    shutil.copyfile(PING, p)
    assert starts(p) and can_execute(p)
    assert exec_lock.deny_execute(p)
    assert not can_execute(p) and not starts(p)
    assert p.read_bytes()[:2] == b"MZ"  # reading (scanning) still works
    assert exec_lock.allow_execute(p)
    assert can_execute(p) and starts(p)


def test_clean_new_program_locked_until_checked(make_container: MakeContainer, downloads: Path) -> None:
    c = make_container([FakeEngine()])
    s, _notes = service(c, downloads)
    s.start()
    try:
        p = downloads / "setup.exe"
        shutil.copyfile(PING, p)
        s.notify_file(str(p))  # the first event locks it at once
        assert not starts(p)
        e = s.locks.get(p)
        assert e is not None and e.state == PENDING
        settle(s, p)
        assert starts(p) and s.locks.get(p) is None
        # Unlocking changes permissions; Windows reports that as a change. It must not lock again.
        time.sleep(1.0)
        s.notify_file(str(p))
        assert can_execute(p) and s.locks.get(p) is None
        # A real content change is a new file: locked again until checked.
        with open(p, "ab") as f:
            f.write(b"\0")
        s.notify_file(str(p))
        assert not can_execute(p)
        settle(s, p)
        assert can_execute(p)
    finally:
        s.stop()
    a = actions(c)
    assert "EXEC_LOCK" in a and "EXEC_UNLOCK" in a


def test_threat_is_quarantined_and_lock_record_cleared(make_container: MakeContainer, downloads: Path) -> None:
    c = make_container([SignatureAV()])
    s, notes = service(c, downloads)
    s.start()
    try:
        p = downloads / "bad.exe"
        p.write_bytes(PING.read_bytes() + MALWARE_MARKER)
        settle(s, p)
        assert not p.exists() and s.locks.get(p) is None
        assert any(t == "已攔截威脅" for _l, t, _m in notes)
    finally:
        s.stop()


def test_threat_stays_locked_without_auto_quarantine_until_user_unlocks(make_container: MakeContainer,
                                                                        downloads: Path) -> None:
    c = make_container([SignatureAV()])
    s, _notes = service(c, downloads)
    s.update(auto_quarantine=False)
    s.start()
    try:
        p = downloads / "bad.exe"
        p.write_bytes(PING.read_bytes() + MALWARE_MARKER)
        settle(s, p)
        e = s.locks.get(p)
        assert p.exists() and e is not None and e.state == HELD and e.reason == "確認威脅"
        assert not can_execute(p)
    finally:
        s.stop()
    assert not can_execute(p)  # stopping protection does not release threats
    assert s.unlock(str(p)) and can_execute(p) and s.locks.get(p) is None
    assert "EXEC_LOCK_HELD" in actions(c)


def test_stop_releases_files_still_waiting(make_container: MakeContainer, downloads: Path) -> None:
    c = make_container([FakeEngine()])
    s, _ = service(c, downloads)
    s.start()
    p = downloads / "wait.exe"
    shutil.copyfile(PING, p)
    s.notify_file(str(p))
    assert not can_execute(p)
    s.stop()
    assert can_execute(p) and s.locks.get(p) is None


def test_pending_lock_from_a_crash_is_checked_at_next_start(make_container: MakeContainer, downloads: Path) -> None:
    c = make_container([FakeEngine()])
    p = downloads / "left.exe"
    shutil.copyfile(PING, p)
    assert exec_lock.deny_execute(p)
    LockRegistry(c.paths.root / "exec_locks.json").put(LockEntry(str(p), PENDING, "等待檢查", ""))
    s, _ = service(c, downloads)
    s.start()
    try:
        s.process_pending(time.monotonic() + 10)
        s.process_pending(time.monotonic() + 20)
        assert can_execute(p) and s.locks.get(p) is None
    finally:
        s.stop()


def test_only_programs_in_downloads_are_locked(make_container: MakeContainer, downloads: Path, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    s, _ = service(c, downloads)
    s.start()
    try:
        txt = downloads / "notes.txt"
        txt.write_text("hi")
        msi = downloads / "setup.msi"
        msi.write_bytes(b"not really an msi")
        other = tmp_path / "elsewhere"
        other.mkdir()
        exe = other / "tool.exe"
        shutil.copyfile(PING, exe)
        for f in (txt, msi, exe):
            s.notify_file(str(f))
        assert s.locks.entries() == [] and can_execute(exe)
    finally:
        s.stop()


def test_option_off_does_not_lock(make_container: MakeContainer, downloads: Path) -> None:
    c = make_container([FakeEngine()])
    s, _ = service(c, downloads)
    s.update(exec_lock=False)
    s.start()
    try:
        p = downloads / "setup.exe"
        shutil.copyfile(PING, p)
        s.notify_file(str(p))
        assert can_execute(p) and s.locks.get(p) is None
    finally:
        s.stop()


def test_user_excluded_program_is_unlocked(make_container: MakeContainer, downloads: Path) -> None:
    c = make_container([FakeEngine()])
    p = downloads / "trusted.exe"
    ExclusionRepository(c.db).add(ExclusionKind.PATH, str(p), "test")
    s, _ = service(c, downloads)
    s.start()
    try:
        shutil.copyfile(PING, p)
        s.notify_file(str(p))
        assert not can_execute(p)
        settle(s, p)
        assert can_execute(p) and s.locks.get(p) is None
    finally:
        s.stop()


def test_registry_survives_restart_and_ignores_garbage(tmp_path: Path) -> None:
    f = tmp_path / "exec_locks.json"
    r = LockRegistry(f)
    r.put(LockEntry(str(tmp_path / "a.exe"), HELD, "可疑", "t"))
    assert LockRegistry(f).get(tmp_path / "A.EXE") is not None  # case-insensitive paths
    f.write_text("{not json", encoding="utf-8")
    assert LockRegistry(f).entries() == []


def test_protection_page_lists_and_unlocks(qtbot, make_container: MakeContainer, downloads: Path,  # type: ignore[no-untyped-def]
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelx.gui.protection_page import ProtectionPage

    c = make_container([SignatureAV()])
    s, _ = service(c, downloads)
    s.update(auto_quarantine=False)
    s.start()
    try:
        p = downloads / "bad.exe"
        p.write_bytes(PING.read_bytes() + MALWARE_MARKER)
        settle(s, p)
        answers = [False, True]
        page = ProtectionPage(s, confirm=lambda *a: answers.pop(0))
        qtbot.addWidget(page)
        assert page.locks_table.rowCount() == 1 and page.unlock_button.isEnabled()
        assert page.options["exec_lock"].isChecked()
        page.locks_table.setCurrentCell(0, 3)
        page.unlock_selected()  # answered "no"
        assert not can_execute(p)
        page.unlock_selected()  # answered "yes"
        assert can_execute(p) and page.locks_table.rowCount() == 0
    finally:
        s.stop()


def test_real_browser_style_download_is_locked_by_the_watcher(make_container: MakeContainer, downloads: Path) -> None:
    """Like Chrome/Edge: write `name.exe.crdownload`, then rename. No manual notify: the watcher does it."""
    c = make_container([FakeEngine()])
    s, _ = service(c, downloads)
    s.start()
    try:
        part = downloads / "app.exe.crdownload"
        shutil.copyfile(PING, part)
        final = downloads / "app.exe"
        part.rename(final)
        deadline = time.monotonic() + 10
        while can_execute(final) and time.monotonic() < deadline:
            time.sleep(0.02)
        locked_after = 10 - (deadline - time.monotonic())
        assert not can_execute(final), "not locked by the watcher"
        assert locked_after < 2.0
    finally:
        s.stop()
    assert can_execute(final)  # released on stop (not checked yet)


def test_m1_program_that_could_not_be_checked_stays_locked(make_container: MakeContainer, downloads: Path) -> None:
    """Audit 8 (M1): an engine failure must not unlock a new program as if it had been checked."""
    c = make_container([FakeEngine(raise_on_scan=RuntimeError("engine failed (test)"))])
    s, notes = service(c, downloads)
    s.start()
    try:
        p = downloads / "setup.exe"
        shutil.copyfile(PING, p)
        s.notify_file(str(p))
        settle(s, p)
        e = s.locks.get(p)
        assert e is not None and e.state == PENDING and "重試" in e.reason
        assert not can_execute(p)
        for _ in range(3):  # retries come due one after another; the engine keeps failing
            assert s.retry_unchecked(time.monotonic() + 3600) == 1
        e = s.locks.get(p)
        assert e is not None and e.state == HELD and e.reason == "無法完整檢查"
        assert not can_execute(p) and not starts(p)
        assert any(t == "新程式無法完整檢查" for _l, t, _m in notes)
        assert s.unlock(str(p)) and can_execute(p)  # the user can still decide
    finally:
        s.stop()


def test_l1_program_blocked_by_someone_else_is_left_alone(make_container: MakeContainer, downloads: Path) -> None:
    """Audit 8 (L1): Sentinel X never takes over (and later removes) a block it did not set."""
    c = make_container([FakeEngine()])
    s, _notes = service(c, downloads)
    p = downloads / "tool.exe"
    shutil.copyfile(PING, p)
    assert exec_lock.deny_execute(p)  # the user's own block, set before protection sees the file
    s.start()
    try:
        s.notify_file(str(p))
        assert s.locks.get(p) is None
        settle(s, p)
        assert not can_execute(p)  # still blocked after the scan: not unlocked by Sentinel X
    finally:
        s.stop()
        exec_lock.allow_execute(p)


def test_l1_links_are_never_locked(tmp_path: Path) -> None:
    target = tmp_path / "real.exe"
    shutil.copyfile(PING, target)
    link = tmp_path / "link.exe"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("creating symbolic links needs Developer Mode or administrator rights here")
    assert exec_lock.is_link(link) and not exec_lock.deny_execute(link)
    assert can_execute(target)


def test_existing_program_is_not_locked_when_windows_updates_it(make_container: MakeContainer, downloads: Path,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    """Found on the user's computer: running a program makes Windows write information to its
    file; that "modified" event locked an existing program, so starting it again failed until it
    was checked. Only new files are locked now."""
    import sentinelx.services.protection_service as ps

    c = make_container([FakeEngine()])
    s, _notes = service(c, downloads)
    p = downloads / "tool.exe"
    shutil.copyfile(PING, p)
    monkeypatch.setattr(ps, "_created_recently", lambda _p: False)  # an old program
    s._seen(str(p), "modified")
    assert s.locks.get(p) is None and can_execute(p)
    s._seen(str(p), "moved")  # a finished download renamed into place
    assert s.locks.get(p) is not None and not can_execute(p)
    s._release(str(p), "test")
    monkeypatch.setattr(ps, "_created_recently", lambda _p: True)  # a new file, still being written
    s._cleared.clear()
    s._seen(str(p), "modified")
    assert s.locks.get(p) is not None
    s._release(str(p), "test")
    assert can_execute(p)
