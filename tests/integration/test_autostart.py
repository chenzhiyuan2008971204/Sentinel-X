"""0.16.0: autostart watch — programs newly set to start with Windows are scanned and reported."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, FakeEngine, SignatureAV
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.engines.base import DetectionEngine
from sentinelx.protection.autostart import (
    AutostartEntry,
    AutostartWatch,
    TaskCache,
    _registry_entries,
    _service_entries,
    command_program,
    powershell_tasks,
    task_command,
)
from sentinelx.services.protection_service import RUN_VALUE, ProtectionService
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
SYS = r"C:\Windows\System32"


def on_disk(*paths: str) -> Callable[[str], bool]:
    known = {p.lower() for p in paths}
    return lambda p: p.lower() in known


# ---------------- which file does a command start ----------------
@pytest.mark.parametrize(("command", "files", "expected"), [
    (r'"C:\Program Files\App\app.exe" --tray', [r"C:\Program Files\App\app.exe"], r"C:\Program Files\App\app.exe"),
    (r"C:\Program Files\App\app.exe /background", [], r"C:\Program Files\App\app.exe"),  # unquoted, with spaces
    (r"rundll32.exe C:\Users\u\AppData\x.dll,Start", [SYS + r"\rundll32.exe"], r"C:\Users\u\AppData\x.dll"),
    (r'powershell.exe -w hidden -File "C:\Users\u\a.ps1"', [SYS + r"\powershell.exe"], r"C:\Users\u\a.ps1"),
    (r"wscript.exe //B C:\Users\u\run.vbs", [SYS + r"\wscript.exe"], r"C:\Users\u\run.vbs"),
    (r"powershell.exe -enc AAAA", [SYS + r"\powershell.exe"], SYS + r"\powershell.exe"),  # no file: the host
    (r"\SystemRoot\System32\svchost.exe -k netsvcs", [], r"C:\Windows\System32\svchost.exe"),
    (r"\??\C:\Drivers\x.exe", [], r"C:\Drivers\x.exe"),
])
def test_command_program(command: str, files: list[str], expected: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert str(command_program(command, on_disk(*files))) == expected


def test_task_file_command() -> None:
    xml = ('<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
           "<Actions><Exec><Command>C:\\Users\\u\\AppData\\up date.exe</Command><Arguments>/q</Arguments></Exec>"
           "</Actions></Task>").encode("utf-16")
    assert task_command(xml) == '"C:\\Users\\u\\AppData\\up date.exe" /q'
    assert task_command(b"not xml") is None


def test_scheduled_tasks_through_windows() -> None:
    out = json.dumps([{"n": "\\Evil", "c": '"C:\\x\\a.exe"', "a": "-s"}, {"n": "\\NoExec", "c": "", "a": ""}])
    assert powershell_tasks(lambda _args: out) == [AutostartEntry("排程工作", "\\Evil", '"C:\\x\\a.exe" -s')]
    assert powershell_tasks(lambda _args: json.dumps({"n": "\\One", "c": "b.exe", "a": None}))[0].command == '"b.exe"'
    assert powershell_tasks(lambda _args: "garbage") == []
    calls: list[int] = []
    t = [0.0]
    cache = TaskCache(lambda: calls.append(1) or [], ttl_s=300, clock=lambda: t[0])
    cache(), cache()
    t[0] = 301
    cache()
    assert len(calls) == 2  # slow reading at most every 5 minutes


class FakeReg:
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE = "HKCU", "HKLM"

    def __init__(self, keys: dict[tuple[str, str], dict[str, object]]) -> None:
        self.keys = keys

    class K:
        def __init__(self, path: tuple[str, str]) -> None:
            self.path = path

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a) -> None:  # type: ignore[no-untyped-def]
            pass

    def OpenKey(self, parent, sub):  # type: ignore[no-untyped-def]  # noqa: N802
        path = (parent.path[0], parent.path[1] + "\\" + sub) if isinstance(parent, FakeReg.K) else (parent, sub)
        if path not in self.keys and not any(k[0] == path[0] and k[1].startswith(path[1] + "\\") for k in self.keys):
            raise OSError("missing")
        return FakeReg.K(path)

    def EnumValue(self, k, i):  # type: ignore[no-untyped-def]  # noqa: N802
        items = [(n, v) for n, v in self.keys.get(k.path, {}).items() if not n.startswith("@")]
        if i >= len(items):
            raise OSError("end")
        return (*items[i], 1)

    def EnumKey(self, k, i):  # type: ignore[no-untyped-def]  # noqa: N802
        subs = sorted({p[1][len(k.path[1]) + 1:].split("\\")[0] for p in self.keys
                       if p[0] == k.path[0] and p[1].startswith(k.path[1] + "\\")})
        if i >= len(subs):
            raise OSError("end")
        return subs[i]

    def QueryValueEx(self, k, name):  # type: ignore[no-untyped-def]  # noqa: N802
        try:
            return self.keys[k.path]["@" + name], 1
        except KeyError:
            raise OSError("no value") from None


def test_registry_and_services() -> None:
    svc = r"SYSTEM\CurrentControlSet\Services"
    reg = FakeReg({
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"): {"Updater": r"C:\u\upd.exe"},
        ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"): {"Once": r"C:\o.exe"},
        ("HKLM", svc + r"\GoodSvc"): {"@Start": 2, "@Type": 0x10, "@ImagePath": r"C:\s\svc.exe"},
        ("HKLM", svc + r"\Manual"): {"@Start": 3, "@Type": 0x10, "@ImagePath": r"C:\s\m.exe"},
        ("HKLM", svc + r"\Driver"): {"@Start": 2, "@Type": 0x1, "@ImagePath": r"C:\d.sys"},
    })
    got = {(e.location, e.name, e.command) for e in _registry_entries(reg) + _service_entries(reg)}
    assert got == {("登錄機碼 Run（目前使用者）", "Updater", r"C:\u\upd.exe"),
                   ("登錄機碼 RunOnce（所有使用者，32 位元）", "Once", r"C:\o.exe"),
                   ("服務（開機自動啟動）", "GoodSvc", r"C:\s\svc.exe")}  # manual services and drivers not read


# ---------------- baseline and new entries ----------------
def test_watch_baseline_new_and_persistent(tmp_path: Path) -> None:
    base = tmp_path / "autostart_baseline.json"
    a, b = AutostartEntry("啟動資料夾", "a.lnk", "a"), AutostartEntry("排程工作", "\\b", "b.exe")
    current = [a]
    seen: list[AutostartEntry] = []
    w = AutostartWatch(base, seen.append, read=lambda: list(current))
    assert w.check_once() == [] and seen == []  # first reading ever = baseline, nothing reported
    current.append(b)
    assert w.check_once() == [b] and seen == [b]
    assert w.check_once() == []  # reported once
    # added while Sentinel X was not running: found at the next start
    c = AutostartEntry("服務（開機自動啟動）", "c", "c.exe")
    current.append(c)
    seen2: list[AutostartEntry] = []
    w2 = AutostartWatch(base, seen2.append, read=lambda: list(current))
    assert w2.check_once() == [c] and seen2 == [c]
    # removed and added again: new again
    current.remove(b)
    w2.check_once()
    current.append(b)
    assert w2.check_once() == [b]
    assert {e.name for e in w2.entries()} == {"a.lnk", "\\b", "c"}


def test_handler_error_does_not_stop_the_watch(tmp_path: Path) -> None:
    current: list[AutostartEntry] = []

    def boom(_e: AutostartEntry) -> None:
        raise RuntimeError("x")

    w = AutostartWatch(tmp_path / "b.json", boom, read=lambda: list(current))
    w.check_once()
    current += [AutostartEntry("x", "1", "1"), AutostartEntry("x", "2", "2")]
    assert len(w.check_once()) == 2


# ---------------- what real-time protection does with a new entry ----------------
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


def protection(c: AppContainer, entries: list[AutostartEntry], tmp_path: Path):  # type: ignore[no-untyped-def]
    notes: list[tuple[str, str, str]] = []
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db), ExclusionRepository(c.db),
                          VerdictRepository(c.db), c.quarantine, c.audit, clamd=None, removable=list,
                          folders=lambda: [("t", tmp_path / "watched")], registry=Reg(),
                          autostart_reader=lambda: list(entries))
    s.notifier = lambda lv, t, m: notes.append((lv, t, m))
    (tmp_path / "watched").mkdir(exist_ok=True)
    return s, notes


def test_new_autostart_threat_is_quarantined(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    entries: list[AutostartEntry] = []
    s, notes = protection(c, entries, tmp_path)
    s.start()
    try:
        assert s.autostart is not None
        s.autostart.check_once()  # baseline
        bad = tmp_path / "evil.exe"
        bad.write_bytes(b"MZ " + MALWARE_MARKER)
        entries.append(AutostartEntry("登錄機碼 Run（目前使用者）", "Evil", f'"{bad}" -hide'))
        assert len(s.autostart.check_once()) == 1
        assert not bad.exists()  # auto-quarantined like any confirmed threat (never deleted)
        assert any(lv == "bad" for lv, _t, _m in notes)
        assert any(a.result == "新增開機自動執行" for a in s.activity())
        with c.db.engine.connect() as con:
            assert "AUTOSTART_ADDED" in {a for (a,) in con.execute(text("SELECT action FROM audit_log"))}
    finally:
        s.stop()


def test_new_unsigned_autostart_is_reported(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    entries: list[AutostartEntry] = []
    s, notes = protection(c, entries, tmp_path)
    s.start()
    try:
        assert s.autostart is not None
        s.autostart.check_once()
        prog = tmp_path / "helper.exe"
        prog.write_bytes(b"MZ harmless unsigned test file")
        entries.append(AutostartEntry("排程工作", "\\Helper", f'"{prog}"'))
        entries.append(AutostartEntry("啟動資料夾", "gone.lnk", str(tmp_path / "gone.lnk")))
        own = AutostartEntry("登錄機碼 Run（目前使用者）", RUN_VALUE, '"C:\\SX\\SentinelX.exe" --background')
        entries.append(own)
        s.autostart.check_once()
        assert prog.exists()  # not a threat: nothing is moved or removed
        texts = [m for lv, t, m in notes if t == "新增開機自動執行"]
        assert any("helper.exe" in m and "沒有有效的數位簽章" in m for m in texts)
        assert any("找不到它要啟動的程式檔" in m for m in texts)
        assert not any("SentinelX.exe" in m for m in texts)  # Sentinel X's own entry is not reported
    finally:
        s.stop()


def test_signed_clean_autostart_is_only_logged(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    entries: list[AutostartEntry] = []
    s, notes = protection(c, entries, tmp_path)
    s.start()
    try:
        assert s.autostart is not None
        s.autostart.check_once()
        signed = tmp_path / "notepad.exe"
        shutil.copy2(r"C:\Windows\System32\notepad.exe", signed)  # Microsoft-signed (catalog or embedded)
        entries.append(AutostartEntry("登錄機碼 Run（目前使用者）", "Notes", f'"{signed}"'))
        s.autostart.check_once()
        rows = [a for a in s.activity() if a.result == "新增開機自動執行"]
        assert len(rows) == 1
        if "有效數位簽章" in rows[0].action:  # embedded signature: logged, no pop-up
            assert not [n for n in notes if n[1] == "新增開機自動執行"]
        else:  # catalog-signed copy elsewhere has no embedded signature: reported like any unsigned file
            assert any("notepad.exe" in m for _l, _t, m in notes)
    finally:
        s.stop()


def test_option_turns_the_watch_off(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    s, _notes = protection(c, [], tmp_path)
    s.start()
    try:
        assert s.autostart is not None and s.autostart.running
        s.update(watch_autostart=False)
        assert s.autostart is None
        s.update(watch_autostart=True)
        assert s.autostart is not None
    finally:
        s.stop()
    assert s.autostart is None


def test_concurrent_readings_do_not_collide(tmp_path: Path) -> None:
    """Found by the full suite: the watch thread and a direct check wrote the baseline at once."""
    import threading

    current = [AutostartEntry("x", str(i), str(i)) for i in range(50)]
    w = AutostartWatch(tmp_path / "b.json", lambda _e: None, read=lambda: list(current))
    errors: list[BaseException] = []

    def run() -> None:
        try:
            for i in range(30):
                current.append(AutostartEntry("y", f"{threading.get_ident()}-{i}", "c"))
                w.check_once()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
