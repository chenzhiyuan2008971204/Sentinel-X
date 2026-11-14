"""Regression tests for engineering audit 8 (2026-11-06). Harmless data only."""

from __future__ import annotations

import psutil
import pytest

from sentinelx.protection.process_guard import ProcessGuard

pytestmark = pytest.mark.integration


def test_h1_guard_asks_program_paths_only_for_new_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    real_exe = psutil.Process.exe

    def counting_exe(self):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return real_exe(self)

    monkeypatch.setattr(psutil.Process, "exe", counting_exe)
    guard = ProcessGuard(lambda: {"0" * 64}, lambda _e: None, protected=lambda _p: True)
    guard.check_once()
    first = calls["n"]
    assert first > 10  # every process looked at once
    calls["n"] = 0
    for _ in range(5):
        guard.check_once()
    assert calls["n"] < first // 4  # afterwards only processes started meanwhile

    calls["n"] = 0
    idle = ProcessGuard(set, lambda _e: None)
    for _ in range(5):
        assert idle.check_once() == []
    assert calls["n"] == 0  # no known threats: nothing to look up at all


# ---------------- H2: VirusTotal scoring ----------------
def _vt(n: int, total: int = 70):  # type: ignore[no-untyped-def]
    from sentinelx.core.enums import EngineOutcomeKind, Severity
    from sentinelx.core.models import DetectionRecord, DetectionResult

    d = DetectionRecord("VirusTotal", "1.0", "VirusTotal.consensus", Severity.HIGH,
                        {"malicious": n, "engines_total": total}, "a" * 64, "t")
    return DetectionResult("VirusTotal", EngineOutcomeKind.FINDINGS, detections=(d,), info={"found": True, "detection_capable": True})


def _clamav(severity_name: str | None):  # type: ignore[no-untyped-def]
    from sentinelx.core.enums import EngineOutcomeKind, Severity
    from sentinelx.core.models import DetectionRecord, DetectionResult

    if severity_name is None:
        return DetectionResult("ClamAV", EngineOutcomeKind.NO_FINDINGS)
    d = DetectionRecord("ClamAV", "1.4", "PUA.Win.Tool.Fake", Severity[severity_name], {}, "a" * 64, "t")
    return DetectionResult("ClamAV", EngineOutcomeKind.FINDINGS, detections=(d,))


def _assess(*outcomes):  # type: ignore[no-untyped-def]
    from pathlib import Path

    from sentinelx.core.models import FileResult
    from sentinelx.core.risk import assess

    return assess(FileResult(Path("x.exe"), 1, None, None, "a" * 64, tuple(outcomes))).classification


def test_h2_virustotal_alone_and_not_independent_of_clamav() -> None:
    from sentinelx.core.enums import Classification

    assert _assess(_clamav(None), _vt(12)) is Classification.SUSPICIOUS  # grey software: reported only
    assert _assess(_clamav(None), _vt(45)) is Classification.CONFIRMED_THREAT  # clear majority
    # ClamAV PUA (medium) + VirusTotal 15 (medium): ClamAV is one of VirusTotal's engines
    assert _assess(_clamav("MEDIUM"), _vt(15)) is Classification.SUSPICIOUS
    assert _assess(_clamav("HIGH"), _vt(5)) is Classification.CONFIRMED_THREAT  # local signature still confirms


def test_h2_virustotal_only_threat_is_not_auto_quarantined(make_container, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from fakes import FakeEngine

    from sentinelx.core.enums import Classification
    from sentinelx.services.protection_service import ProtectionService
    from sentinelx.storage.scan_repository import ExclusionRepository, FileRow, ScanRepository
    from sentinelx.storage.verdict_repository import VerdictRepository

    c = make_container([FakeEngine()])
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          folders=lambda: [], registry=object())
    calls: list[int] = []
    s._quarantine.quarantine_verdict = lambda vid, *a, **k: calls.append(vid)  # type: ignore[method-assign]
    notes: list[tuple[str, str, str]] = []
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    f = tmp_path / "tool.exe"
    f.write_bytes(b"MZ harmless")
    s._act_verdict(FileRow(str(f), "a" * 64, 11, True, None, ["VirusTotal: VirusTotal.consensus"], [],
                           Classification.CONFIRMED_THREAT, "中", 7))
    assert calls == [] and f.exists()
    assert notes and notes[-1][0] == "bad" and "沒有自動隔離" in notes[-1][2]
    s._act_verdict(FileRow(str(f), "a" * 64, 11, True, None, ["ClamAV: Eicar-Signature", "VirusTotal: VirusTotal.consensus"],
                           [], Classification.CONFIRMED_THREAT, "高", 8))
    assert calls == [8]  # a local engine agreed: the usual automatic quarantine


# ---------------- H4: interference with Sentinel X is noticed ----------------
def _start(paths):  # type: ignore[no-untyped-def]
    from fakes import FakeEngine

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.enums import PrivilegeLevel

    return bootstrap(paths, console_log=False, privilege=PrivilegeLevel.STANDARD, engines=[FakeEngine()])


def _titles(c) -> list[str]:  # type: ignore[no-untyped-def]
    return [t for t, _m in c.self_check.warnings]


def test_h4_normal_restarts_are_quiet_and_interference_is_reported(app_paths) -> None:  # type: ignore[no-untyped-def]
    from conftest import _drop_log_handlers

    c = _start(app_paths)
    assert c.self_check.first_run and _titles(c) == []
    c.protection.update(auto_quarantine=False)  # Sentinel X's own save: not a warning later
    c.shutdown()
    c = _start(app_paths)
    assert not c.self_check.first_run and _titles(c) == []

    # Killed: no normal shutdown, so the session marker stays.
    c.db.dispose()
    _drop_log_handlers()
    c = _start(app_paths)
    assert _titles(c) == ["Sentinel X 上次沒有正常結束"]
    c.shutdown()

    # Another program turns protection off in the settings file while Sentinel X is closed.
    cfg = app_paths.config_file
    cfg.write_text(cfg.read_text(encoding="utf-8").replace('"enabled": true', '"enabled": false')
                   .replace('"auto_quarantine": false', '"auto_quarantine": true'), encoding="utf-8")
    c = _start(app_paths)
    assert _titles(c) == ["設定檔被其他程式修改"]
    c.shutdown()
    c = _start(app_paths)
    assert _titles(c) == []  # reported once; the changed file is the new baseline
    from sqlalchemy import text

    with c.db.engine.connect() as con:
        acts = {a for (a,) in con.execute(text("SELECT action FROM audit_log"))}
    assert {"PREVIOUS_SESSION_UNEXPECTED_END", "CONFIG_CHANGED_EXTERNALLY", "CONFIG_SAVED"} <= acts
    assert c.audit.verify(full=True).ok  # the chain holding the hashes is intact
    c.shutdown()
    _drop_log_handlers()


def test_h4_removed_sign_in_start_is_restored_and_reported(app_paths) -> None:  # type: ignore[no-untyped-def]
    from conftest import _drop_log_handlers

    values: dict[str, str] = {}

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

        def QueryValueEx(self, _k, name):  # type: ignore[no-untyped-def]  # noqa: N802
            if name not in values:
                raise OSError("missing")
            return values[name], 1

        def SetValueEx(self, _k, name, _r, _t, v) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
            values[name] = v

        def DeleteValue(self, _k, name) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
            values.pop(name, None)

    c = _start(app_paths)
    c.protection._registry = Reg()
    c.protection.update(enabled=True, start_at_login=True)
    assert values  # created by the setting
    assert c.protection.apply_autostart() is False  # present: nothing restored
    values.clear()  # another program removed it
    assert c.protection.apply_autostart() is True and values
    c.shutdown()
    _drop_log_handlers()


# ---------------- M2: VirusTotal in real-time protection ----------------
def test_m2_realtime_virustotal_only_for_brought_in_files_and_never_waits(db, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import time

    from test_virustotal import FakeVT, engine, exe, payload

    from sentinelx.core.cancel import CancelToken
    from sentinelx.core.enums import EngineOutcomeKind
    from sentinelx.engines.virustotal import RealtimeVirusTotal

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    sysdir = tmp_path / "Program Files"
    sysdir.mkdir()
    a = [exe(downloads, f"setup{i}.exe", bytes([i])) for i in range(6)]
    b = [exe(sysdir, f"lib{i}.dll", bytes([100 + i])) for i in range(5)]
    fake = FakeVT({t.sha256: payload(0) for t in a + b})
    inner = engine(db, fake, tmp_path, per_minute=4, max_wait=60.0)  # manual scans may wait
    rt = RealtimeVirusTotal(inner, lambda p: downloads in p.parents)
    started = time.monotonic()
    out = rt.scan_batch(a + b, CancelToken())
    assert time.monotonic() - started < 5  # never waits for the per-minute limit
    assert len(fake.requests) == 4  # only Downloads files, and only what the minute allows
    assert all(out[t].kind is EngineOutcomeKind.SKIPPED and "下載" in out[t].info["skip_reason"] for t in b)
    assert sum(out[t].kind is EngineOutcomeKind.SKIPPED for t in a) == 2

    (tmp_path / "q2").mkdir()
    capped = RealtimeVirusTotal(engine(db, FakeVT(), tmp_path / "q2"), lambda p: True, cap=0)
    t = exe(downloads, "new.exe", b"new")
    assert "手動掃描" in capped.scan_batch([t], CancelToken())[t].info["skip_reason"]


# ---------------- M5: user folders watched for the ransomware warning ----------------
def test_m5_user_folders_watched_without_whole_drive_protection(make_container, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from fakes import FakeEngine

    from sentinelx.services.protection_service import ProtectionService
    from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
    from sentinelx.storage.verdict_repository import VerdictRepository

    c = make_container([FakeEngine()])
    pics, docs = tmp_path / "Pictures", tmp_path / "Documents"
    pics.mkdir()
    docs.mkdir()
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          registry=object(), user_folders=lambda: [docs, pics])
    s.update(watch_all_drives=False, watch_downloads=False, watch_temp=False, watch_desktop_documents=False)
    got = [p for _l, p in s._fixed_folders()]
    assert pics in got and docs in got
    s.update(ransomware_watch=False)
    got = [p for _l, p in s._fixed_folders()]
    assert pics not in got and docs not in got


# ---------------- M3: real-time throughput ----------------
def test_m3_full_batches_continue_without_pausing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Measured before the fix: at most 100 files a second (50 per batch, then a 0.5 s pause), so a
    burst of 20 000 files had only 61 % checked after two minutes. Now: 100 % in about 14 s."""
    import threading
    import time

    from sentinelx.protection.realtime import FolderScanner

    files = []
    for i in range(1000):
        f = tmp_path / f"f{i:04d}.txt"
        f.write_text("harmless", encoding="utf-8")
        files.append(f)
    seen: set[str] = set()
    lock = threading.Lock()

    def scan(paths):  # type: ignore[no-untyped-def]
        with lock:
            seen.update(map(str, paths))

    fs = FolderScanner(scan, exclude=[], settle_s=0.0)
    for f in files:
        fs.notify(str(f))
    for p in fs._pending.values():
        p.size = 8  # already measured once: ready at the next check
    started = time.monotonic()
    fs.start()
    try:
        while len(seen) < len(files) and time.monotonic() - started < 30:
            time.sleep(0.05)
    finally:
        fs.stop()
    assert len(seen) == len(files)
    assert time.monotonic() - started < 5  # the old pause alone took 10 s for 1 000 files


# ---------------- L4: old "0 detections" ----------------
def test_l4_old_virustotal_result_is_not_a_full_check() -> None:
    from datetime import UTC, datetime, timedelta

    from sentinelx.engines.virustotal import TS, _stale

    now = datetime.now(UTC)
    assert not _stale((now - timedelta(days=10)).strftime(TS))
    assert _stale((now - timedelta(days=400)).strftime(TS))
    assert _stale(None)


# ---------------- L2: content changed, size and time faked back ----------------
def test_l2_content_change_with_restored_time_is_rescanned(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import os
    import time

    from sentinelx.protection import fileid
    from sentinelx.protection.realtime import FolderScanner

    f = tmp_path / "doc.txt"
    f.write_bytes(b"AAAA harmless")
    st = os.stat(f)
    before = fileid.stamp(str(f))
    time.sleep(0.05)
    f.write_bytes(b"BBBB harmless")  # same size
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))  # old last-write time put back
    after = fileid.stamp(str(f))
    assert before is not None and after is not None
    assert before[:2] == after[:2]  # what the old check compared looks unchanged
    assert before != after  # the change time gives it away

    scanned: list[str] = []
    fs = FolderScanner(lambda ps: scanned.extend(map(str, ps)), exclude=[], settle_s=0.0)

    def settle() -> None:
        fs.notify(str(f))
        fs.process_ready(time.monotonic() + 10)
        fs.process_ready(time.monotonic() + 20)

    settle()
    assert scanned == [str(f)]
    fs.remember_content(str(f), fileid.sha256(str(f)))  # as protection does after the scan
    settle()  # unchanged file, late duplicate event: not scanned twice
    assert scanned == [str(f)]
    time.sleep(0.05)
    os.chmod(f, 0o444)  # attribute change only (like Windows noting a program's first run)
    os.chmod(f, 0o666)
    settle()
    assert scanned == [str(f)]  # same content: no new scan
    st = os.stat(f)
    time.sleep(0.05)  # Windows moves file times in ticks of about 16 ms
    f.write_bytes(b"CCCC harmless")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    settle()
    assert scanned == [str(f), str(f)]  # the faked change is scanned again


# ---------------- rule files are not auto-quarantined ----------------
def test_detection_rule_files_are_not_auto_quarantined(make_container, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Found on the user's computer: ClamAV and YARA matched YARA Forge's own rule file and
    real-time protection quarantined it. Rule text contains the patterns it describes."""
    from fakes import FakeEngine

    from sentinelx.core.enums import Classification
    from sentinelx.services.protection_service import ProtectionService, is_rule_source
    from sentinelx.storage.scan_repository import ExclusionRepository, FileRow, ScanRepository
    from sentinelx.storage.verdict_repository import VerdictRepository

    rules = tmp_path / "community.yar"
    rules.write_text('rule Webshell_Test {\n  strings:\n    $a = "eval(base64_decode("\n  condition:\n    $a\n}\n',
                     encoding="utf-8")
    sigs = tmp_path / "local.ndb"
    sigs.write_text("Test.Sig:0:*:4142434445\n", encoding="utf-8")
    fake_rules = tmp_path / "tool.yar"
    fake_rules.write_bytes(b"MZ\x90\x00\x03\x00rule x { condition: true }")  # a program with a rule-file name
    notes_txt = tmp_path / "notes.yar"
    notes_txt.write_text("just some notes, not rules", encoding="utf-8")
    assert is_rule_source(str(rules)) and is_rule_source(str(sigs))
    assert not is_rule_source(str(fake_rules)) and not is_rule_source(str(notes_txt))

    c = make_container([FakeEngine()])
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          folders=lambda: [], registry=object())
    calls: list[int] = []
    s._quarantine.quarantine_verdict = lambda vid, *a, **k: calls.append(vid)  # type: ignore[method-assign]
    notes: list[tuple[str, str, str]] = []
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    for i, f in enumerate((rules, fake_rules)):
        s._act_verdict(FileRow(str(f), "a" * 64, 10, True, None, ["ClamAV: Html.Backdoor.Test"], [],
                               Classification.CONFIRMED_THREAT, "高", 10 + i))
    assert calls == [11]  # only the disguised program is quarantined
    assert any(t == "偵測到規則檔" for _l, t, _m in notes)


# ---------------- found on the user's computer while measuring memory ----------------
def test_write_sampler_survives_processes_without_a_name(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Every snapshot failed with KeyError 'name' on the user's computer."""
    import psutil

    from sentinelx.protection.ransomware import WriteSampler

    class P:
        def __init__(self, pid: int, info: dict, wb: int) -> None:  # type: ignore[type-arg]
            self.pid, self.info, self._wb = pid, info, wb

        def io_counters(self):  # type: ignore[no-untyped-def]
            return type("IO", (), {"write_bytes": self._wb})()

    procs = [P(1, {"pid": 1}, 10), P(2, {"pid": 2, "name": "a.exe", "exe": r"C:\a.exe"}, 20)]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    rows = WriteSampler._read()
    assert (1, "", "", 10) in rows and (2, "a.exe", r"C:\a.exe", 20) in rows


def test_locked_programs_are_checked_before_a_backlog(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import time

    from sentinelx.protection.realtime import MAX_BATCH, FolderScanner

    backlog = []
    for i in range(MAX_BATCH * 3):
        f = tmp_path / f"b{i:04d}.txt"
        f.write_text("x", encoding="utf-8")
        backlog.append(f)
    locked = tmp_path / "zz-setup.exe"
    locked.write_bytes(b"MZ harmless")
    batches: list[list[str]] = []
    fs = FolderScanner(lambda ps: batches.append([p.name for p in ps]), exclude=[], settle_s=0.0,
                       first=lambda p: p.endswith("zz-setup.exe"))
    for f in [*backlog, locked]:
        fs.notify(str(f))
    for p in fs._pending.values():
        p.size = 1 if not p.path.endswith(".exe") else 11
    fs.process_ready(time.monotonic() + 5)
    assert "zz-setup.exe" in batches[0]  # first batch, although it arrived last


# ---------------- memory-saving mode ----------------
def test_memory_saving_mode(make_container, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from fakes import FakeEngine

    from sentinelx.services.protection_service import ProtectionService
    from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
    from sentinelx.storage.verdict_repository import VerdictRepository

    clam, other = FakeEngine("ClamAV"), FakeEngine("YARA")

    class Clamd:
        STARTING = "starting"
        state = "stopped"
        detail = "未啟動"
        starts = stops = 0

        def start(self) -> None:
            Clamd.starts += 1

        def stop(self) -> None:
            Clamd.stops += 1

        def engine(self):  # type: ignore[no-untyped-def]
            return None

    downloads, elsewhere = tmp_path / "Downloads", tmp_path / "Program Files"
    downloads.mkdir()
    elsewhere.mkdir()
    a, b = downloads / "setup.exe", elsewhere / "lib.dll"
    a.write_bytes(b"MZ a")
    b.write_bytes(b"MZ b")
    c = make_container([clam, other])
    s = ProtectionService(c.paths, c.config, c.config_store, [clam, other], ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=Clamd(), removable=list,  # type: ignore[arg-type]
                          folders=lambda: [], registry=object(), lock_areas=lambda: [downloads])
    s.update(low_memory=True)
    s.start()
    try:
        assert Clamd.starts == 0  # not resident
        s._scan_files([a, b])
        assert [p.name for p in clam.scanned] == ["setup.exe"]  # ClamAV only for brought-in files
        assert sorted(p.name for p in other.scanned) == ["lib.dll", "setup.exe"]
        s.update(low_memory=False)
        assert Clamd.starts == 1
        s.update(low_memory=True)
        assert Clamd.stops == 1
    finally:
        s.stop()


# ---------------- M4 follow-up: memory grew with every file event ----------------
@pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows known folders")
def test_known_folder_lookup_makes_no_new_ctypes_types() -> None:
    """Seen on the user's computer: 20,000 new files raised memory from 56 MB to 514 MB. Each
    lookup defined a new ctypes structure, and ctypes keeps every POINTER(type) for good."""
    import ctypes

    from sentinelx.protection import locations

    locations._lookup_known_folder(locations.FOLDERID_DOCUMENTS)  # prepares the signature once
    cache = ctypes._pointer_type_cache  # type: ignore[attr-defined]
    before = len(cache)
    first = locations._lookup_known_folder(locations.FOLDERID_DOCUMENTS)
    for _ in range(300):
        assert locations._lookup_known_folder(locations.FOLDERID_DOCUMENTS) == first
    assert len(cache) == before
    assert first is not None and first.is_dir()


def test_known_folder_is_remembered_briefly(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asked for every file event; remembered for a short time only, because the user (or
    OneDrive) can move Desktop, Documents and Downloads."""
    import sys
    from pathlib import Path

    from sentinelx.protection import locations

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(locations, "_known_cache", {})
    asked: list[object] = []
    answers = iter([Path("C:/A"), Path("D:/B")])
    monkeypatch.setattr(locations, "_lookup_known_folder", lambda fid: asked.append(fid) or next(answers))
    fid = locations.FOLDERID_DESKTOP
    assert locations.known_folder(fid, now=100.0) == Path("C:/A")
    assert locations.known_folder(fid, now=100.0 + locations.KNOWN_FOLDER_TTL_S - 1) == Path("C:/A")
    assert len(asked) == 1
    assert locations.known_folder(fid, now=100.0 + locations.KNOWN_FOLDER_TTL_S + 1) == Path("D:/B")  # moved
    assert len(asked) == 2


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows change time")
def test_file_stamp_prepares_its_windows_api_once(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.protection import fileid

    f = tmp_path / "a.txt"
    f.write_text("x")
    first = fileid.stamp(str(f))
    api = fileid._api
    for _ in range(200):
        assert fileid.stamp(str(f)) == first
    assert fileid._api is api and api is not None
