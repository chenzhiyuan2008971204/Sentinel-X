"""Real collectors with harmless synthetic activity: ping to 127.0.0.1, a loopback TCP
connection, and file operations in a temp folder. Plus the full pipeline producing an alert
when a (copied, harmless) program that local intel lists as malicious is executed."""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import AlertStatus, EventSource, PrivilegeLevel, Severity, TrustLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.hash_intel import HashIntelEngine
from sentinelx.monitor.collectors import (
    FolderWatchCollector,
    NetworkCollector,
    ProcessCollector,
    defender_collector,
    security_log_collector,
    sysmon_collector,
)
from sentinelx.monitor.events import EventKind
from sentinelx.services.monitor_service import MonitorService
from sentinelx.storage.event_repository import EventRepository
from sentinelx.storage.intel_repository import IntelStore

pytestmark = [pytest.mark.integration, pytest.mark.windows,
              pytest.mark.skipif(sys.platform != "win32", reason="Windows telemetry")]
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
PING = Path(r"C:\Windows\System32\PING.EXE")


def wait_for(fn, timeout: float = 10.0, step: float = 0.3):  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = fn()
        if r:
            return r
        time.sleep(step)
    return fn()


def test_process_collector_sees_new_process() -> None:
    c = ProcessCollector(ignore_self=False)
    c.start()
    proc = subprocess.Popen([str(PING), "-n", "4", "127.0.0.1"], stdout=subprocess.DEVNULL)
    try:
        seen: list = []  # type: ignore[type-arg]
        found = wait_for(lambda: [e for e in (seen.extend(c.poll()) or seen) if e.pid == proc.pid])
        assert found, "ping.exe was not observed"
        e = found[0]
        assert e.kind is EventKind.PROCESS_CREATE and e.process_name.lower() == "ping.exe"
        assert e.ppid is not None and "127.0.0.1" in (e.command_line or "")
    finally:
        proc.wait(15)


def test_process_collector_ignores_own_children_by_default() -> None:
    c = ProcessCollector()
    c.start()
    proc = subprocess.Popen([str(PING), "-n", "3", "127.0.0.1"], stdout=subprocess.DEVNULL)
    time.sleep(1.0)
    events = c.poll()
    proc.wait(15)
    assert not [e for e in events if e.pid == proc.pid]


def test_network_collector_sees_loopback_connection() -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    c = NetworkCollector(ignore_self=False)
    assert c.status().available
    c.start()
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    try:
        evs = c.poll()
        hit = [e for e in evs if e.remote_port == port and e.remote_addr == "127.0.0.1"]
        assert hit and hit[0].kind is EventKind.NET_CONNECT and hit[0].details["protocol"] == "TCP"
        assert c.poll() == [] or all(e.remote_port != port for e in c.poll())  # reported once
    finally:
        cli.close()
        conn.close()
        srv.close()


def test_folder_watch_real_events(tmp_path: Path) -> None:
    c = FolderWatchCollector([tmp_path])
    c.start()
    try:
        f = tmp_path / "sub" / "報告.txt"
        f.parent.mkdir()
        f.write_text("one", encoding="utf-8")
        f.write_text("two", encoding="utf-8")
        f.rename(tmp_path / "sub" / "renamed.txt")
        (tmp_path / "sub" / "renamed.txt").unlink()
        got: list = []  # type: ignore[type-arg]

        def kinds():  # type: ignore[no-untyped-def]
            got.extend(c.poll())
            return {e.kind for e in got} >= {EventKind.FILE_CREATE, EventKind.FILE_MOVE, EventKind.FILE_DELETE}

        assert wait_for(kinds, 10), [(e.kind, e.target_path) for e in got]
        assert any(e.target_path and e.target_path.endswith("報告.txt") for e in got)
    finally:
        c.stop()


def test_real_eventlog_source_statuses() -> None:
    d = defender_collector().status()
    if not d.available:
        pytest.skip(f"Defender channel unavailable: {d.detail}")
    sysmon = sysmon_collector().status()
    sec = security_log_collector().status()
    from sentinelx.app.privilege import detect_privilege

    if detect_privilege() is PrivilegeLevel.STANDARD:
        assert not sec.available and sec.requires_admin
    if not sysmon.available:
        assert sysmon.requires_admin or "尚未安裝" in sysmon.detail


def test_defender_collector_start_and_poll_without_history() -> None:
    c = defender_collector()
    if not c.status().available:
        pytest.skip("Defender channel unavailable")
    c.start()
    assert isinstance(c.poll(), list)  # starts at the newest record; history is not replayed


def test_full_pipeline_alert_when_listed_program_runs(make_container: MakeContainer, tmp_path: Path) -> None:
    sample = tmp_path / "downloads" / "sample.exe"
    sample.parent.mkdir()
    shutil.copyfile(PING, sample)  # harmless program, listed as "malicious" only in local test intel
    sha = hashlib.sha256(sample.read_bytes()).hexdigest()

    c0 = make_container([])
    intel = IntelStore(c0.db)
    lst = tmp_path / "list.txt"
    lst.write_text(f"{sha},Test.ListedSample\n", encoding="utf-8")
    intel.import_file(lst, source_name="TestIntel", trust=TrustLevel.HIGH)
    c = make_container([HashIntelEngine(intel)])
    s = c.scans.run_scan([sample], CancelToken())
    assert s.confirmed == 1

    svc = MonitorService(c.paths, c.config, c.config_store, EventRepository(c.db), c.quarantine._verdicts, c.audit,
                         PrivilegeLevel.STANDARD,
                         collector_factory=lambda cfg: [ProcessCollector(ignore_self=False, interval_s=0.5),
                                                        FolderWatchCollector([tmp_path / "downloads"])])
    c.config.monitor.poll_interval_s = 1.0
    svc.start()
    try:
        proc = subprocess.Popen([str(sample), "-n", "4", "127.0.0.1"], stdout=subprocess.DEVNULL)
        (tmp_path / "downloads" / "note.txt").write_text("x")
        alerts = wait_for(lambda: [a for a in svc.alerts() if a.rule_id == "R1_THREAT_EXECUTED"], 15)
        proc.wait(15)
        assert alerts, [(e.kind, e.process_path) for e in svc.events()]
        a = alerts[0]
        assert a.severity is Severity.HIGH and a.status is AlertStatus.OPEN
        assert any(str(sample).lower() in f.lower() for f in a.observed_facts)
        assert any("確認威脅" in f for f in a.observed_facts) and "不會終止程序" in a.analysis
        evs = svc.alert_events(a)
        assert evs and evs[0].kind is EventKind.PROCESS_CREATE and evs[0].source is EventSource.PSUTIL
        assert wait_for(lambda: svc.events(kind=EventKind.FILE_CREATE, text="note.txt"), 10)
        assert proc.poll() is not None  # the monitored process ran to completion; nothing was killed
    finally:
        svc.stop()
    assert not svc.running
    svc.set_alert_status(a.id, AlertStatus.ACKNOWLEDGED)
    assert svc.alerts() == [] and svc.alerts(include_closed=True)[0].status is AlertStatus.ACKNOWLEDGED


def test_alert_dedup_and_retention(make_container: MakeContainer) -> None:
    from sentinelx.monitor.events import SecurityEventIn
    from sentinelx.storage.event_repository import AlertIn

    c = make_container([])
    repo = EventRepository(c.db)
    ids = [e.id for e in repo.insert([SecurityEventIn(EventSource.PSUTIL, EventKind.FILE_MODIFY, "2026-11-02T00:00:00Z",
                                                      target_path=f"C:\\x\\{i}") for i in range(30)])]
    a = AlertIn("R", "t", Severity.LOW, ["f"], "a", [ids[0]], "key")
    first, created = repo.add_alert(a)
    second, created2 = repo.add_alert(AlertIn("R", "t", Severity.LOW, ["f"], "a", [ids[1]], "key"))
    assert created and not created2 and first == second
    assert repo.alerts()[0].event_ids == [ids[0], ids[1]]
    assert repo.prune(10) == 20 and repo.count() == 10
    assert min(e.id for e in repo.query(limit=100)) == ids[20]  # newest kept


def test_watch_dir_management(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([])
    c.monitor.add_watch_dir(tmp_path)
    assert c.monitor.watch_dirs == [str(tmp_path)]
    assert c.config_store.load().monitor.watch_dirs == [str(tmp_path)]  # persisted
    with pytest.raises(ValueError):
        c.monitor.add_watch_dir(tmp_path)  # duplicate
    with pytest.raises(ValueError):
        c.monitor.add_watch_dir(c.paths.root)  # own data folder
    with pytest.raises(ValueError):
        c.monitor.add_watch_dir(tmp_path / "missing")
    c.monitor.remove_watch_dir(str(tmp_path).upper())
    assert c.monitor.watch_dirs == []


def test_sysmon_config_saved_and_valid_xml(make_container: MakeContainer, tmp_path: Path) -> None:
    import xml.etree.ElementTree as ET

    c = make_container([])
    dest = c.monitor.save_sysmon_config(tmp_path / "sysmon.xml")
    root = ET.parse(dest).getroot()
    assert root.tag == "Sysmon" and root.find("EventFiltering") is not None
    with pytest.raises(ValueError):
        c.monitor.save_sysmon_config(dest)  # never overwrites


def test_elevation_request_is_audited(make_container: MakeContainer) -> None:
    c = make_container([])
    c.monitor._relauncher = lambda: False
    assert c.monitor.request_elevation() is False
    with c.db.engine.connect() as conn:
        from sqlalchemy import text

        assert "ELEVATION_REQUESTED" in [r[0] for r in conn.execute(text("SELECT action FROM audit_log"))]
