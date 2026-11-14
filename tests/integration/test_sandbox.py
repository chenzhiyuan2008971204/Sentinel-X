"""0.16.0: trial-run room, against a fake VBoxManage (the real VM is never touched by tests)."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fakes import FakeEngine

from sentinelx.app.bootstrap import AppContainer
from sentinelx.app.config import ScanLimits
from sentinelx.core.enums import Classification
from sentinelx.engines.base import DetectionEngine
from sentinelx.sandbox.engine import findings
from sentinelx.sandbox.trial import MONITOR, Sandbox
from sentinelx.sandbox.vbox import Result, VBox, VBoxError
from sentinelx.services.sandbox_service import SandboxService
from sentinelx.storage.scan_repository import ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
QUIET: dict[str, Any] = {"started": True, "processes": [{"name": "setup.exe", "cmd": "setup.exe"}],
                         "persistence": {}, "decoys_total": 40, "decoys_changed": 0, "defender_new_detections": 0}


class FakeVBoxManage:
    """Imitates the VBoxManage commands Sentinel X uses; records every call."""

    def __init__(self, report: dict[str, Any] | None = None, *, exists: bool = True, snapshot: bool = True,
                 fail_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.exists, self.snapshot, self.state = exists, snapshot, "poweroff"
        self.report = report or QUIET
        self.fail_on = fail_on
        self.password_files_seen: list[str] = []
        self.dvd = True
        self.nic = "none"
        self.nic_at_snapshot: str | None = None

    def __call__(self, args: Sequence[str], timeout: float) -> Result:
        a = list(args[1:])
        self.calls.append(a)
        for x in a:
            if x.startswith("--user-password-file=") or (Path(x).name.startswith(".pw-")):
                self.password_files_seen.append(x.split("=", 1)[-1])
        if self.fail_on and self.fail_on in a:
            return Result(1, "", f"failure in {self.fail_on}")
        cmd = a[0]
        if cmd == "--version":
            return Result(0, "7.2.22r175245\n", "")
        if cmd == "showvminfo":
            dvd = '"SATA-1-0"="C:\\vm\\Unattended-aux-iso.viso"\n' if self.dvd else ""
            return (Result(0, f'name="x"\nVMState="{self.state}"\nnic1="{self.nic}"\n{dvd}', "") if self.exists
                    else Result(1, "", "not found"))
        if cmd == "storageattach" and "none" in a:
            self.dvd = False
        if cmd == "snapshot":
            if a[2] == "list":
                return Result(0, 'SnapshotName="clean"\n', "") if self.snapshot else Result(1, "", "no snapshots")
            if a[2] == "take":
                self.snapshot = True
                self.nic_at_snapshot = self.nic
                self.state_at_snapshot = self.state
            if a[2] == "restore":
                self.state = "saved"
            return Result(0, "", "")
        if cmd == "startvm":
            self.state = "running"
        if cmd == "modifyvm" and "--nic1" in a:
            self.nic = a[a.index("--nic1") + 1]
        if cmd == "guestcontrol" and a[2] == "run" and any(x.endswith("slmgr.vbs") for x in a):
            return Result(0, "Name: Windows(R), EnterpriseEval edition\nLicense Status: Licensed\n", "")
        if cmd == "guestcontrol" and a[2] == "run" and any(x.endswith("shutdown.exe") for x in a):
            self.state = "poweroff"
        if cmd == "controlvm" and a[2] in ("poweroff", "acpipowerbutton"):
            self.state = "poweroff"
        if cmd == "createvm":
            self.exists = True
        if cmd == "unregistervm":
            self.exists, self.snapshot = False, False
        if cmd == "guestproperty":
            return Result(0, "Value: 1\n", "")
        if cmd == "guestcontrol" and a[2] == "copyfrom":
            dest = Path(a[a.index("--target-directory") + 1])
            import ntpath

            (dest / ntpath.basename(a[-1])).write_text(json.dumps(self.report), encoding="utf-8")
        return Result(0, "", "")

    def names(self) -> list[str]:
        return [" ".join(c[:3]) for c in self.calls]


def sandbox(tmp_path: Path, fake: FakeVBoxManage, *, built_days_ago: int | None = 1,
            now: datetime | None = None) -> Sandbox:
    base = tmp_path / "SX-Sandbox"
    (base / "iso").mkdir(parents=True)
    (base / "iso" / "win.iso").write_bytes(b"iso")
    now = now or datetime(2026, 11, 6, tzinfo=UTC)
    sb = Sandbox(base, VBox(Path("VBoxManage.exe"), fake), now=lambda: now)
    if built_days_ago is not None:
        sb._save_state(built_at=(now - timedelta(days=built_days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return sb


def sample(tmp_path: Path, name: str = "setup.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(b"MZ harmless test placeholder")
    return p


# ---------------- grading ----------------
def test_findings_and_strength() -> None:
    rep = dict(QUIET, defender_new_detections=1, defender_threat_names=["Trojan:Win32/Fake"], decoys_changed=25,
               defender_disabled=True, persistence={"run_keys": ["HKCU\\...\\Run\\x=y"], "tasks": ["\\evil"]},
               hosts_changed=True, dropped_executables=["C:\\a.exe"], network_attempts=["1.2.3.4:443 (x)"])
    got = {r: s for r, s, _t, _e in findings(rep)}
    assert got["Sandbox.DefenderDetected"] == got["Sandbox.DecoysModified"] == got["Sandbox.DefenderDisabled"] == "strong"
    assert got["Sandbox.Persistence.run_keys"] == got["Sandbox.Persistence.tasks"] == got["Sandbox.HostsChanged"] == "moderate"
    assert got["Sandbox.DroppedExecutables"] == got["Sandbox.NetworkAttempts"] == "weak"
    assert findings(QUIET) == []
    assert findings(dict(QUIET, decoys_changed=3)) == []  # a few changed decoys are not ransomware-like


# ---------------- status ----------------
def test_status_and_90_day_rebuild(tmp_path: Path) -> None:
    fake = FakeVBoxManage()
    st = sandbox(tmp_path, fake, built_days_ago=10).status()
    assert st.ready and st.days_left == 80 and not st.rebuild_due and "80 天" in st.detail
    st = sandbox(tmp_path / "b", fake, built_days_ago=81).status()
    assert st.rebuild_due and st.days_left == 9
    no_vbox = Sandbox(tmp_path / "c", VBox(None, fake)).status()
    assert not no_vbox.ready and "VirtualBox" in no_vbox.detail


# ---------------- build ----------------
def test_build_installs_unattended_without_network_and_takes_snapshot(tmp_path: Path) -> None:
    fake = FakeVBoxManage(exists=False, snapshot=False)
    sb = sandbox(tmp_path, fake, built_days_ago=None)
    sb._wait = lambda cond, timeout, cancel, poll: True  # type: ignore[method-assign]
    sb.build()
    modify = next(c for c in fake.calls if c[0] == "modifyvm")
    assert modify[modify.index("--nic1") + 1] == "none"  # no network adapter at all
    assert modify[modify.index("--cpus") + 1] == "1"  # 2+ vCPUs hang in UEFI under Hyper-V
    assert "--clipboard-mode" in modify and "--drag-and-drop" in modify
    unattended = next(c for c in fake.calls if c[:2] == ["unattended", "install"])
    assert any(x.startswith("--user-password-file=") for x in unattended)
    assert not any(x.startswith("--user-password=") for x in unattended)  # never on the command line
    assert any(c[:3] == ["snapshot", sb.vm, "take"] for c in fake.calls)
    assert sb.status().ready and sb.status().days_left == 90
    i_boot = next(i for i, c in enumerate(fake.calls) if c[0] == "modifyvm" and "--boot1" in c)
    assert fake.calls[i_boot][fake.calls[i_boot].index("--boot1") + 1] == "disk"
    assert i_boot < next(i for i, c in enumerate(fake.calls) if c[0] == "startvm")  # set before the first start
    assert not any(x.startswith("--start-vm") for x in unattended)
    detach = next(c for c in fake.calls if c[0] == "storageattach" and "none" in c)
    assert detach[detach.index("--storagectl") + 1] == "SATA" and detach[detach.index("--port") + 1] == "1"
    starts = [i for i, c in enumerate(fake.calls) if c[0] == "startvm"]
    assert starts[0] < fake.calls.index(detach) < starts[1]  # disc removed between copying and first start
    # network only while building (online activation), removed before the clean snapshot
    nat = next(i for i, c in enumerate(fake.calls) if c[0] == "modifyvm" and c[-2:] == ["--nic1", "nat"])
    assert starts[0] < nat < starts[1]  # never during the WinPE copy step
    assert fake.nic_at_snapshot == "none" and fake.nic == "none"
    assert fake.state_at_snapshot == "poweroff"  # a shut-down snapshot: trial runs start Windows fresh
    post = next(x for x in unattended if x.startswith("--post-install-command="))
    assert "slmgr.vbs /ato" in post and "Administrators sxsandbox" in post
    # a plain VM: no disguise, no extra accounts, no administrator steps
    assert not any(c[0] == "setextradata" for c in fake.calls)
    assert modify[modify.index("--memory") + 1] == "4096"
    create = next(c for c in fake.calls if c[:2] == ["createmedium", "disk"])
    assert create[create.index("--size") + 1] == "65536"
    host = next(x for x in unattended if x.startswith("--hostname="))
    assert host == "--hostname=SXSANDBOX.local"
    runs = [c for c in fake.calls if c[:3] == ["guestcontrol", sb.vm, "run"]]
    assert runs and all(c[c.index("--username") + 1] == "sxsandbox" for c in runs)
    assert not any("-Stage" in c for c in runs)
    assert all(not Path(p).exists() for p in fake.password_files_seen)  # plain-text file removed
    assert (sb.base / "guest.pw").exists() and b"sxsandbox" not in (sb.base / "guest.pw").read_bytes()


def test_first_setup_restarts_a_vm_that_powered_itself_off(tmp_path: Path) -> None:
    """Seen on the user's computer: during first setup Windows powered the VM off before the
    Guest Additions reported a signed-in user. The build starts it again instead of waiting 5 h."""
    fake = FakeVBoxManage()
    sb = sandbox(tmp_path, fake)
    answers = iter([False, False, True])
    sb.vbox.guest_ready = lambda vm: next(answers)  # type: ignore[method-assign]
    fake.state = "poweroff"
    assert not sb._ready_or_restart()
    assert fake.calls[-1][0] == "startvm" and fake.state == "running"
    assert not sb._ready_or_restart()  # running but not signed in yet: no second start
    assert sum(c[0] == "startvm" for c in fake.calls) == 1
    assert sb._ready_or_restart()
    sb.vbox.guest_ready = lambda vm: False  # type: ignore[method-assign]
    with pytest.raises(VBoxError):
        for _ in range(10):
            fake.state = "poweroff"
            sb._ready_or_restart()


# ---------------- trial run ----------------
def test_run_file_restores_before_and_after(tmp_path: Path) -> None:
    fake = FakeVBoxManage(dict(QUIET, defender_new_detections=1))
    sb = sandbox(tmp_path, fake)
    rep = sb.run_file(sample(tmp_path), seconds=60)
    assert rep["defender_new_detections"] == 1
    restores = [i for i, c in enumerate(fake.calls) if c[:3] == ["snapshot", sb.vm, "restore"]]
    runs = [i for i, c in enumerate(fake.calls) if c[:3] == ["guestcontrol", sb.vm, "run"]]
    assert restores[0] < runs[0] < restores[-1]  # clean before, clean again after
    copied = [c[-1] for c in fake.calls if c[:3] == ["guestcontrol", sb.vm, "copyto"]]
    assert any(c.endswith("setup.exe") for c in copied)
    monitor = [c for c in copied if c.endswith(".ps1")]
    assert monitor and "monitor" not in monitor[0].lower()  # the monitor runs under a random name
    assert all(not Path(p).exists() for p in fake.password_files_seen)


def test_run_file_restores_even_when_it_fails(tmp_path: Path) -> None:
    fake = FakeVBoxManage(fail_on="copyto")
    sb = sandbox(tmp_path, fake)
    with pytest.raises(VBoxError):
        sb.run_file(sample(tmp_path))
    assert fake.calls[-1][:3] == ["snapshot", sb.vm, "restore"]


def test_run_refused_when_not_built(tmp_path: Path) -> None:
    sb = sandbox(tmp_path, FakeVBoxManage(snapshot=False))
    with pytest.raises(VBoxError, match="還沒建立"):
        sb.run_file(sample(tmp_path))


def test_sample_never_runs_on_the_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only VBoxManage is ever started: the sample path is never a program the host runs."""
    started: list[Any] = []
    real_popen = subprocess.Popen

    def spy(args, *a, **k):  # type: ignore[no-untyped-def]
        started.append(args)
        return real_popen(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", spy)
    fake = FakeVBoxManage(dict(QUIET))
    sandbox(tmp_path, fake).run_file(sample(tmp_path, "evil.exe"))
    assert started == []  # the fake runner replaces VBoxManage; nothing else was launched
    assert all("evil.exe" not in c[0] for c in fake.calls)


# ---------------- service: verdicts ----------------
def service(c: AppContainer, sb: Sandbox) -> SandboxService:
    return SandboxService(sb, c.engines, ScanRepository(c.db), VerdictRepository(c.db), ScanLimits(), c.audit)


def test_trial_records_a_confirmed_threat(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    fake = FakeVBoxManage(dict(QUIET, defender_new_detections=1, defender_threat_names=["Trojan:Win32/Fake"]))
    res = service(c, sandbox(tmp_path, fake)).trial(sample(tmp_path))
    assert res.classification is Classification.CONFIRMED_THREAT and "確定有危險" in res.summary
    assert res.file is not None and res.file.verdict_id is not None
    assert any("Defender" in b for b in res.behaviours)


def test_trial_with_persistence_is_suspicious(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    fake = FakeVBoxManage(dict(QUIET, persistence={"run_keys": ["HKCU\\Run\\x=y"]}))
    res = service(c, sandbox(tmp_path, fake)).trial(sample(tmp_path))
    assert res.classification is Classification.SUSPICIOUS and "可疑" in res.summary


def test_quiet_trial_never_claims_safe(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    res = service(c, sandbox(tmp_path, FakeVBoxManage(QUIET))).trial(sample(tmp_path))
    assert "不代表一定安全" in res.summary and res.behaviours == []
    assert res.classification is not Classification.CONFIRMED_THREAT
    with c.db.engine.connect() as conn:
        from sqlalchemy import text

        assert "SANDBOX_TRIAL" in [r[0] for r in conn.execute(text("SELECT action FROM audit_log"))]


def test_large_installer_is_not_skipped_by_the_size_limit(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    big = tmp_path / "big.exe"
    with open(big, "wb") as f:
        f.write(b"MZ")
        f.seek(150 * 1024 * 1024)
        f.write(b"\0")
    fake = FakeVBoxManage(dict(QUIET, defender_new_detections=1))
    res = service(c, sandbox(tmp_path, fake)).trial(big)
    assert res.classification is Classification.CONFIRMED_THREAT


def test_automatic_rebuild_when_due(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    fake = FakeVBoxManage()
    sb = sandbox(tmp_path, fake, built_days_ago=85)
    sb._wait = lambda cond, timeout, cancel, poll: True  # type: ignore[method-assign]
    svc = service(c, sb)
    notes: list[tuple[str, str, str]] = []
    svc.notifier = lambda *n: notes.append(n)
    assert svc.rebuild_if_due()
    svc._rebuild_thread.join(30)  # type: ignore[union-attr]
    assert any(t == "試跑室重建完成" for _l, t, _m in notes)
    assert not svc.status().rebuild_due and svc.status().days_left == 90
    assert not svc.rebuild_if_due()  # nothing to do now


# ---------------- guest script ----------------
@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parser")
def test_guest_monitor_script_parses() -> None:
    """Parsed only, never executed on the host."""
    cmd = ("$e=$null; [System.Management.Automation.Language.Parser]::ParseFile('" + str(MONITOR) +
           "', [ref]$null, [ref]$e) | Out-Null; $e.Count")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == "0", r.stdout + r.stderr


# ---------------- page ----------------
def test_page_flow(qtbot, make_container: MakeContainer, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.gui.sandbox_page import SandboxPage

    c = make_container([FakeEngine()])
    not_built = SandboxPage(service(c, sandbox(tmp_path / "a", FakeVBoxManage(snapshot=False))), finished=True)
    qtbot.addWidget(not_built)
    assert not not_built.run_button.isEnabled() and not_built.build_button.isEnabled()
    quarantined: list[int] = []
    s = sample(tmp_path)
    page = SandboxPage(service(c, sandbox(tmp_path / "b", FakeVBoxManage(dict(QUIET, defender_new_detections=1)))),
                       confirm=lambda *a: True, picker=lambda _w: s,
                       quarantine=lambda vid: quarantined.append(vid) or "ok", finished=True)
    qtbot.addWidget(page)
    assert page.run_button.isEnabled() and "剩" in page.status_label.text()
    page.start_trial()
    qtbot.waitUntil(lambda: not page.busy and page.result is not None, timeout=30_000)
    assert "確定有危險" in page.result_title.text() and page.quarantine_button.isVisibleTo(page)
    page.quarantine_result()
    qtbot.waitUntil(lambda: not page.busy and bool(quarantined), timeout=10_000)  # runs in the background
    assert quarantined and not page.quarantine_button.isVisibleTo(page)


def test_unfinished_sandbox_is_clearly_disabled(qtbot, make_container: MakeContainer, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Audit 8 (H3): until the real build works, no button pretends the feature is usable."""
    from sentinelx.gui.sandbox_page import SandboxPage

    c = make_container([FakeEngine()])
    fake = FakeVBoxManage()
    page = SandboxPage(service(c, sandbox(tmp_path, fake)), confirm=lambda *a: True, picker=lambda _w: sample(tmp_path),
                       finished=False)
    qtbot.addWidget(page)
    assert not page.run_button.isEnabled() and not page.build_button.isEnabled()
    assert "開發中" in page.status_label.text()
    page.start_trial()
    page.start_build()
    assert not page.busy and page.result is None
    assert not any(cmd[0] in ("startvm", "createvm") for cmd in fake.calls)


def test_trial_runs_in_the_sandbox_folder(tmp_path: Path) -> None:
    fake = FakeVBoxManage()
    sb = sandbox(tmp_path, fake)
    sb.run_file(sample(tmp_path, "installer.exe"))
    copies = [c for c in fake.calls if c[:3] == ["guestcontrol", sb.vm, "copyto"]]
    assert all(c[c.index("--target-directory") + 1] == "C:\\SX\\" for c in copies)  # VirtualBox 7: folder ends with \\
    assert all(c[c.index("--username") + 1] == "sxsandbox" for c in copies)
    monitor = next(c for c in fake.calls if c[:3] == ["guestcontrol", sb.vm, "run"] and "-Sample" in c)
    assert monitor[monitor.index("-Sample") + 1] == "C:\\SX\\installer.exe" and "-NoMouse" in monitor


def test_answer_file_gives_the_vm_account_one_group(tmp_path: Path) -> None:
    """Seen in the real VM (Windows 11 24H2): with "administrators;users" the account ended up in
    no group, so the Guest Additions installer had no rights and the build never finished."""
    vbox_dir = tmp_path / "VirtualBox"
    (vbox_dir / "UnattendedTemplates").mkdir(parents=True)
    (vbox_dir / "UnattendedTemplates" / "win_nt6_unattended.xml").write_text(
        '<settings pass="windowsPE"><RunAsynchronous>x</RunAsynchronous></settings>'
        "<Group>administrators;users</Group>"
        "<CommandLine>cmd.exe /c @@VBOX_INSERT_AUXILIARY_INSTALL_DIR@@VBOXPOST.CMD --vista-or-newer</CommandLine>",
        encoding="utf-8")
    base = tmp_path / "SX-Sandbox"
    base.mkdir()
    sb = Sandbox(base, VBox(vbox_dir / "VBoxManage.exe", FakeVBoxManage()))
    out = sb._answer_template()
    assert out is not None
    text = out.read_text(encoding="utf-8")
    assert "<Group>Administrators</Group>" in text and "administrators;users" not in text
    assert r"C:\SXSetup\VBOXPOST.CMD" in text and "<RunSynchronous>" in text


def test_newest_iso_is_used(tmp_path: Path) -> None:
    import os

    sb = sandbox(tmp_path, FakeVBoxManage(), built_days_ago=None)
    old, new = sb.base / "iso" / "win.iso", sb.base / "iso" / "26300-eval.iso"
    new.write_bytes(b"iso")
    os.utime(old, (1_700_000_000, 1_700_000_000))
    assert sb.iso() == new  # an expired evaluation ISO is replaced by dropping in a newer one


def test_build_stops_when_windows_cannot_activate(tmp_path: Path) -> None:
    fake = FakeVBoxManage(exists=False, snapshot=False)
    sb = sandbox(tmp_path, fake, built_days_ago=None)
    sb._activated = lambda: False  # type: ignore[method-assign]
    sb._wait = lambda cond, timeout, cancel, poll: cond() if cond == sb._activated else True  # type: ignore[method-assign]
    with pytest.raises(VBoxError):
        sb.build()
    assert not fake.snapshot  # no clean snapshot of a VM that would power off every hour


def test_first_setup_restarts_windows_once_when_additions_never_report(tmp_path: Path) -> None:
    """Seen in the VM: the Guest Additions were installed at the end of setup but their service
    only starts after a restart. After SETUP_RESTART_S the build shuts Windows down cleanly and
    the next poll starts it again."""
    from sentinelx.sandbox import trial

    fake = FakeVBoxManage()
    sb = sandbox(tmp_path, fake)
    clock = [0.0]
    sb._clock = lambda: clock[0]  # type: ignore[method-assign]
    sb.vbox.guest_ready = lambda vm: False  # type: ignore[method-assign]
    fake.state = "running"
    assert not sb._ready_or_restart()
    clock[0] = trial.SETUP_RESTART_S - 1
    assert not sb._ready_or_restart()
    assert not any(c[:3] == ["controlvm", sb.vm, "acpipowerbutton"] for c in fake.calls)
    clock[0] = trial.SETUP_RESTART_S + 1
    assert not sb._ready_or_restart()
    assert fake.calls[-1][:3] == ["controlvm", sb.vm, "acpipowerbutton"] and fake.state == "poweroff"
    assert not sb._ready_or_restart()
    assert fake.calls[-1][0] == "startvm"  # started again; the timer starts over
    assert not sb._ready_or_restart()
    assert fake.calls[-1][0] != "controlvm"


def test_guest_program_is_not_repeated_as_its_first_argument(tmp_path: Path) -> None:
    """VirtualBox 7.2: the arguments after "--" must not repeat the program (cscript then tried to
    run cscript.exe as a script, seen in the VM)."""
    fake = FakeVBoxManage()
    sb = sandbox(tmp_path, fake)
    sb.vbox.exec(sb.vm, "sxsandbox", tmp_path / "pw", r"C:\Windows\System32\cscript.exe", ["//nologo", "x.vbs"], 10)
    call = fake.calls[-1]
    assert call[call.index("--") + 1:] == ["//nologo", "x.vbs"]


def test_monitor_that_never_started_is_tried_again(tmp_path: Path) -> None:
    """Seen in the VM: right after boot PowerShell can start too slowly for the Guest Additions,
    so the monitor never runs ("Waiting for guest process (flags 0x1) failed"). It is tried again."""
    fake = FakeVBoxManage(dict(QUIET))
    sb = sandbox(tmp_path, fake)
    sb._wait = lambda cond, timeout, cancel, poll: bool(cond())  # type: ignore[method-assign]
    real, fails = fake.__call__, [1]

    def flaky(args: Sequence[str], timeout: float) -> Result:
        if "-Sample" in args and fails:
            fails.pop()
            fake.calls.append(list(args[1:]))
            return Result(1, "", "error: Waiting for guest process (flags 0x1) failed: The guest did not respond")
        return real(args, timeout)

    sb.vbox._run = flaky  # type: ignore[method-assign]
    report = sb.run_file(sample(tmp_path), seconds=5)
    assert report["started"] and sum("-Sample" in c for c in fake.calls) == 2


# ---------------- VirtualBox version (audit 8, M6) ----------------
class _Response:
    def __init__(self, body: bytes, url: str) -> None:
        self.body, self.url = body, url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *a: object) -> None:
        pass

    def geturl(self) -> str:
        return self.url

    def read(self, n: int = -1) -> bytes:
        return self.body[:n]


def test_virtualbox_version_text_is_read_strictly() -> None:
    from sentinelx.sandbox import vbox_version as vv

    assert vv.parse("7.2.22r175245\n") == (7, 2, 22) and vv.parse("garbage") is None
    ok = lambda body, url=vv.LATEST_URL: (lambda req, timeout: _Response(body, url))  # noqa: E731
    assert vv.fetch_latest(ok(b"7.2.24\n")) == (7, 2, 24)
    assert vv.fetch_latest(ok(b"<html>7.2.24</html>")) is None  # not the one-line file
    assert vv.fetch_latest(ok(b"9.9.9\n", "https://evil.example/x")) is None  # redirected elsewhere

    def offline(req: object, timeout: float) -> _Response:
        raise OSError("no network")

    assert vv.fetch_latest(offline) is None


def test_old_virtualbox_refuses_trial_and_build(tmp_path: Path) -> None:
    fake = FakeVBoxManage()  # reports 7.2.22
    sb = sandbox(tmp_path, fake)
    sb._latest = lambda: (7, 2, 24)
    with pytest.raises(VBoxError, match="太舊"):
        sb.run_file(sample(tmp_path))
    with pytest.raises(VBoxError, match="太舊"):
        sb.build()
    assert not any(c[0] in ("startvm", "createvm", "unregistervm") for c in fake.calls)  # VM never touched
    st = sb.status()
    assert "太舊" in st.detail and st.version_check is not None and not st.version_check.ok


def test_older_than_the_verified_release_is_refused_even_offline(tmp_path: Path) -> None:
    class Old(FakeVBoxManage):
        def __call__(self, args: Sequence[str], timeout: float) -> Result:
            if list(args[1:]) == ["--version"]:
                return Result(0, "7.1.12r168000\n", "")
            return super().__call__(args, timeout)

    fake = Old()
    sb = sandbox(tmp_path, fake)
    sb._latest = lambda: None  # cannot reach the internet
    with pytest.raises(VBoxError, match="7.2.22"):
        sb.run_file(sample(tmp_path))
    assert not any(c[0] == "startvm" for c in fake.calls)


def test_current_virtualbox_runs_and_newest_release_is_read_once_a_day(tmp_path: Path) -> None:
    fake = FakeVBoxManage()
    now = datetime(2026, 11, 9, tzinfo=UTC)
    sb = sandbox(tmp_path, fake, now=now)
    asked: list[int] = []
    sb._latest = lambda: asked.append(1) or (7, 2, 22)
    sb._wait = lambda cond, timeout, cancel, poll: True  # type: ignore[method-assign]
    sb.run_file(sample(tmp_path))
    sb.run_file(sample(tmp_path))
    assert len(asked) == 1  # remembered for a day
    chk = sb.status().version_check
    assert chk is not None and chk.ok and chk.checked_online and "最新版" in chk.message
    sb._now = lambda: now + timedelta(days=2)
    sb.run_file(sample(tmp_path))
    assert len(asked) == 2


def test_offline_check_still_runs_but_says_so(tmp_path: Path) -> None:
    sb = sandbox(tmp_path, FakeVBoxManage())
    sb._latest = lambda: None
    assert "試跑前會先向官方網站確認" in sb.status().version_check.message  # type: ignore[union-attr]
    chk = sb.check_virtualbox()
    assert chk.ok and not chk.checked_online
    sb._save_state(vbox_latest="7.2.22", vbox_checked="2026-10-01T00:00:00Z")  # over a day old
    assert "試跑前會再確認" in sb.check_virtualbox().message
    steps: list[str] = []
    sb._wait = lambda cond, timeout, cancel, poll: True  # type: ignore[method-assign]
    sb.run_file(sample(tmp_path), progress=steps.append)
    assert any("無法連線確認" in m for m in steps)


def test_page_disables_trial_for_old_virtualbox(qtbot, make_container: MakeContainer, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.gui.sandbox_page import SandboxPage

    c = make_container([FakeEngine()])
    sb = sandbox(tmp_path, FakeVBoxManage())
    sb._save_state(vbox_latest="7.2.30", vbox_checked="2026-11-06T00:00:00Z")
    page = SandboxPage(service(c, sb), finished=True)
    qtbot.addWidget(page)
    assert not page.run_button.isEnabled() and not page.build_button.isEnabled()
    assert "太舊" in page.status_label.text() and "virtualbox.org" in page.status_label.text()
