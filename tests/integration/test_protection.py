"""Real-time protection on harmless files: folder scanning, automatic quarantine, download gate,
removable drives, process guard, vault watch, resident clamd (fake process), autostart."""

from __future__ import annotations

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
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.engines.base import DetectionEngine
from sentinelx.protection import locations
from sentinelx.protection.clamd_manager import ClamdManager
from sentinelx.protection.process_guard import ProcessGuard
from sentinelx.protection.realtime import FolderScanner, VaultWatch
from sentinelx.services.protection_service import ProtectionService, autostart_command
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
FAKE_CLAMD = [sys.executable, "-I", str(Path(__file__).parent.parent / "data" / "fake_clamd_proc.py")]


class FakeRegistry:
    HKEY_CURRENT_USER = 1
    REG_SZ = 1

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    class _Key:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a) -> None:  # type: ignore[no-untyped-def]
            pass

    def CreateKey(self, *_a):  # type: ignore[no-untyped-def]  # noqa: N802
        return self._Key()

    OpenKey = CreateKey  # noqa: N815

    def SetValueEx(self, _k, name, _r, _t, value) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        self.values[name] = value

    def DeleteValue(self, _k, name) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        if name not in self.values:
            raise OSError(2, "missing")
        del self.values[name]

    def QueryValueEx(self, _k, name):  # type: ignore[no-untyped-def]  # noqa: N802
        if name not in self.values:
            raise OSError(2, "missing")
        return self.values[name], 1


def service(c: AppContainer, folder: Path, *, drives: list[Path] | None = None,
            reg: FakeRegistry | None = None) -> tuple[ProtectionService, list[tuple[str, str, str]]]:
    notes: list[tuple[str, str, str]] = []
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None,
                          removable=lambda: list(drives or []), folders=lambda: [("測試", folder)],
                          registry=reg or FakeRegistry())
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    return s, notes


def settle(s: ProtectionService, path: Path) -> None:
    s.notify_file(str(path))
    s.process_pending(time.monotonic() + 10)  # size recorded
    s.process_pending(time.monotonic() + 20)  # unchanged: scanned


def actions(c: AppContainer) -> list[str]:
    with c.db.engine.connect() as con:
        return [a for (a,) in con.execute(text("SELECT action FROM audit_log"))]


@pytest.fixture
def watched(tmp_path: Path) -> Path:
    d = tmp_path / "watched"
    d.mkdir()
    return d


def test_confirmed_threat_is_quarantined_and_reported(make_container: MakeContainer, watched: Path) -> None:
    c = make_container([SignatureAV()])
    s, notes = service(c, watched)
    s.start()
    try:
        bad = watched / "bad.bin"
        bad.write_bytes(b"x " + MALWARE_MARKER)
        settle(s, bad)
        assert not bad.exists()  # moved into the vault (never deleted)
        assert [q.original_path for q in c.quarantine.items()] == [str(bad)]
        assert notes and notes[-1][0] == "bad" and "已自動隔離" in notes[-1][2]
        assert s.activity()[0].action == "已自動隔離" and s.status().blocked == 1
        assert {"AUTO_QUARANTINE", "PROTECTION_START"} <= set(actions(c))
        assert c.scans.history() == [] and c.reports.scan_jobs() == []  # realtime batches stay out of manual history
    finally:
        s.stop()
    assert "PROTECTION_STOP" in actions(c)


def test_auto_quarantine_off_only_notifies(make_container: MakeContainer, watched: Path) -> None:
    c = make_container([SignatureAV()])
    s, notes = service(c, watched)
    s.update(auto_quarantine=False)
    s.start()
    try:
        bad = watched / "bad.bin"
        bad.write_bytes(MALWARE_MARKER)
        settle(s, bad)
        assert bad.exists() and c.quarantine.items() == []
        assert notes[-1][1] == "發現威脅" and "自動隔離已關閉" in notes[-1][2]
    finally:
        s.stop()


def test_suspicious_clean_and_partial_files(make_container: MakeContainer, watched: Path) -> None:
    c = make_container([FakeEngine()])
    s, notes = service(c, watched)
    s.start()
    try:
        sus = watched / "sus.bin"
        sus.write_bytes(MALWARE_MARKER)
        settle(s, sus)
        assert sus.exists() and notes[-1][0] == "warn" and "可疑" in notes[-1][1]
        n = len(notes)
        ok = watched / "fine.txt"
        ok.write_text("hello")
        settle(s, ok)
        part = watched / "setup.exe.crdownload"
        part.write_bytes(MALWARE_MARKER)
        settle(s, part)
        assert len(notes) == n  # clean file outside Downloads: quiet; partial download: ignored
    finally:
        s.stop()


def test_own_data_folder_is_never_scanned(make_container: MakeContainer) -> None:
    c = make_container([SignatureAV()])
    s, _ = service(c, c.paths.root)
    s.start()
    try:
        f = c.paths.root / "rules-copy.yar"
        f.write_bytes(MALWARE_MARKER)
        s.notify_file(str(f))
        assert s.process_pending(time.monotonic() + 30) == 0 and f.exists()
    finally:
        s.stop()


def test_growing_file_waits_until_stable(tmp_path: Path) -> None:
    seen: list[list[Path]] = []
    fs = FolderScanner(seen.append, exclude=[], settle_s=1.0)
    f = tmp_path / "big.bin"
    f.write_bytes(b"a")
    fs.notify(str(f))
    t = time.monotonic()
    assert fs.process_ready(t + 2) == 0  # first look records the size
    f.write_bytes(b"ab")
    assert fs.process_ready(t + 4) == 0  # grew: waits again
    assert fs.process_ready(t + 6) == 1 and seen == [[f]]


def test_download_gate_conclusions(make_container: MakeContainer, watched: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = make_container([SignatureAV()])
    monkeypatch.setattr(locations, "downloads", lambda: watched)
    s, notes = service(c, watched)
    s.start()
    try:
        signed = watched / "signed-setup.exe"
        shutil.copyfile(sys.executable, signed)
        settle(s, signed)
        level, title, msg = notes[-1]
        assert title == "下載檢查完成" and "未發現已知威脅" in msg and ("簽章" in msg)
        unsigned = watched / "tool.exe"
        unsigned.write_bytes(b"MZ" + b"\x00" * 200)
        with open(f"{unsigned}:Zone.Identifier", "w", encoding="utf-8") as z:
            z.write("[ZoneTransfer]\nZoneId=3\n")
        settle(s, unsigned)
        assert notes[-1][0] == "warn" and "來自網際網路" in notes[-1][2] and "安全" not in notes[-1][2].replace("不代表安全", "")
        txt = watched / "readme.txt"
        txt.write_text("hi")
        before = len(notes)
        settle(s, txt)
        assert len(notes) == before  # the gate is for installers and executables only
    finally:
        s.stop()


def test_removable_drive_is_scanned_on_insert(make_container: MakeContainer, tmp_path: Path, watched: Path) -> None:
    c = make_container([SignatureAV()])
    usb = tmp_path / "usb"
    usb.mkdir()
    (usb / "autorun-payload.bin").write_bytes(MALWARE_MARKER)
    drives: list[Path] = []
    s, notes = service(c, watched, drives=drives)
    s.start()
    try:
        drives.append(usb)
        assert s.check_drives() == [usb]
        assert any(t == "偵測到卸除式磁碟" for _l, t, _m in notes)
        assert not (usb / "autorun-payload.bin").exists() and str(usb) in s.status().drives
        assert s.check_drives() == []  # already known
    finally:
        s.stop()


def test_autostart_follows_settings(make_container: MakeContainer, watched: Path) -> None:
    c = make_container([])
    reg = FakeRegistry()
    s, _ = service(c, watched, reg=reg)
    s.update(enabled=True)
    assert "--background" in reg.values["SentinelX"] and s.autostart_enabled()
    s.update(start_at_login=False)
    assert "SentinelX" not in reg.values
    s.update(start_at_login=True)
    s.update(enabled=False)
    assert "SentinelX" not in reg.values
    assert autostart_command(r"C:\App\SentinelX.exe", True) == '"C:\\App\\SentinelX.exe" --background'


def test_threat_hashes_include_confirmed_and_quarantined(make_container: MakeContainer, watched: Path) -> None:
    c = make_container([SignatureAV()])
    s, _ = service(c, watched)
    s.update(auto_quarantine=False)
    s.start()
    try:
        bad = watched / "bad.bin"
        bad.write_bytes(MALWARE_MARKER + b"1")
        settle(s, bad)
        import hashlib

        assert hashlib.sha256(bad.read_bytes()).hexdigest() in s.threat_hashes()
    finally:
        s.stop()


# ---------------- process guard ----------------

PING = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "PING.EXE"


def _start_grandchild(exe: Path) -> psutil.Process:
    """Start `exe` (a copy of ping.exe: harmless, runs for a minute) via an intermediate process,
    because the guard ignores Sentinel X's own children."""
    code = "import subprocess, sys; subprocess.Popen([sys.argv[1], '-n', '60', '127.0.0.1'])"
    subprocess.run([sys.executable, "-c", code, str(exe)], check=True, timeout=60)
    for _ in range(100):
        for p in psutil.process_iter(["exe"]):
            if p.info["exe"] and os.path.normcase(p.info["exe"]) == os.path.normcase(str(exe)):
                return p
        time.sleep(0.1)
    raise AssertionError("process not found")


@pytest.mark.security
@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Windows processes")
def test_process_guard_terminates_exact_hash_only(tmp_path: Path) -> None:
    import hashlib

    threat = tmp_path / "threat.exe"
    shutil.copyfile(PING, threat)
    sha = hashlib.sha256(threat.read_bytes()).hexdigest()
    events = []
    guard = ProcessGuard(lambda: {sha}, events.append, protected=lambda _p: False)
    p = _start_grandchild(threat)
    try:
        killed = guard.check_once()
        assert [e.pid for e in killed if e.killed] == [p.pid] and events[0].detail == "已終止"
        p.wait(10)
        other = ProcessGuard(lambda: {"0" * 64}, events.append, protected=lambda _p: False)
        q = _start_grandchild(threat)
        assert other.check_once() == [] and q.is_running()  # different hash: untouched
        q.kill()
    finally:
        if p.is_running():
            p.kill()


@pytest.mark.security
@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Windows processes")
def test_process_guard_never_kills_protected_or_critical(tmp_path: Path) -> None:
    import hashlib

    for name, protected in (("signed.exe", True), ("explorer.exe", False)):
        d = tmp_path / name.split(".")[0]
        d.mkdir()
        exe = d / name
        shutil.copyfile(PING, exe)
        sha = hashlib.sha256(exe.read_bytes()).hexdigest()
        guard = ProcessGuard(lambda s=sha: {s}, lambda _e: None, protected=lambda _p, v=protected: v)
        p = _start_grandchild(exe)
        try:
            [ev] = guard.check_once()
            assert not ev.killed and p.is_running() and "不終止" in ev.detail
        finally:
            p.kill()


# ---------------- vault watch ----------------

def test_vault_watch_alerts_on_foreign_changes(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    alerts: list[tuple[str, str]] = []
    age = [1000.0]
    w = VaultWatch(vault, lambda: age[0], lambda k, p: alerts.append((k, p)))
    w.start()
    try:
        (vault / "dropped.exe").write_bytes(b"x")
        deadline = time.monotonic() + 5
        while not alerts and time.monotonic() < deadline:
            time.sleep(0.1)
        assert alerts and alerts[0][1].endswith("dropped.exe")
        time.sleep(0.5)
        assert len([a for a in alerts if a[1].endswith("dropped.exe")]) == 1  # created+modified: one alert
        alerts.clear()
        age[0] = 0.0  # Sentinel X is changing the vault itself
        (vault / "own.sxq").write_bytes(b"y")
        time.sleep(1.0)
        assert alerts == []
    finally:
        w.stop()


# ---------------- resident clamd ----------------

def test_clamd_manager_with_fake_clamd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_CLAMD_DELAY", "1")
    db = tmp_path / "王小明" / "clamav-db"
    db.mkdir(parents=True)
    states: list[str] = []
    m = ClamdManager(None, db, tmp_path / "clamd", launcher=FAKE_CLAMD, on_state=lambda s, _d: states.append(s))
    m.start()
    try:
        assert m.state == ClamdManager.STARTING and m.engine() is None
        deadline = time.monotonic() + 30
        while m.state != ClamdManager.READY and time.monotonic() < deadline:
            time.sleep(0.2)
        assert m.state == ClamdManager.READY and "127.0.0.1" in m.detail
        conf = (tmp_path / "clamd" / "clamd.conf").read_text(encoding="utf-8")
        assert "TCPAddr 127.0.0.1" in conf and str(db) in conf
        from sentinelx.core.cancel import CancelToken
        from sentinelx.core.models import ScanTarget

        f = tmp_path / "bad.bin"
        f.write_bytes(MALWARE_MARKER)
        t = ScanTarget(f, "a" * 64, f.stat().st_size)
        engine = m.engine()
        assert engine is not None
        assert engine.scan_batch([t], CancelToken())[t].detections[0].rule_id == "Sentinel.Test.Marker-1"
    finally:
        m.stop()
    assert m.state == ClamdManager.STOPPED and states[:2] == ["starting", "ready"]


def test_clamd_manager_errors_are_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = ClamdManager(tmp_path / "missing" / "clamd.exe", tmp_path, tmp_path / "w")
    m.start()
    assert m.state == ClamdManager.ERROR and "clamd.exe" in m.detail
    m2 = ClamdManager(None, tmp_path, tmp_path / "w2", launcher=FAKE_CLAMD, ready_timeout_s=20)
    monkeypatch.setenv("FAKE_CLAMD_MODE", "crash")
    m2.start()
    deadline = time.monotonic() + 20
    while m2.state == ClamdManager.STARTING and time.monotonic() < deadline:
        time.sleep(0.2)
    assert m2.state == ClamdManager.ERROR and "結束" in m2.detail
    m2.stop()
