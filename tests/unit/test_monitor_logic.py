"""Monitor parsing, collectors with scripted inputs, and correlation rules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinelx.app.config import MonitorSettings
from sentinelx.app.privilege import elevation_command
from sentinelx.core.enums import Classification, EventSource, Severity
from sentinelx.monitor import wevt
from sentinelx.monitor.collectors import (
    EventLogCollector,
    FolderWatchCollector,
    defender_event,
    parse_event_xml,
    security_event,
    sysmon_event,
)
from sentinelx.monitor.correlation import Correlator, ThreatIndex, ThreatInfo, has_encoded_command
from sentinelx.monitor.events import EventKind, StoredEvent
from sentinelx.scanner.exclusions import norm_path

pytestmark = pytest.mark.unit
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def evxml(rid: int, eid: int, data: dict[str, str], t: str = "2026-11-02T06:41:38.0355402Z") -> str:
    items = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='{NS}'><System><EventID>{eid}</EventID><TimeCreated SystemTime='{t}'/>"
            f"<EventRecordID>{rid}</EventRecordID></System><EventData>{items}</EventData></Event>")


# ---------------- parsing ----------------
def test_parse_event_xml() -> None:
    p = parse_event_xml(evxml(42, 1, {"Image": "C:\\中文\\a.exe"}))
    assert (p.record_id, p.event_id, p.time) == (42, 1, "2026-11-02T06:41:38Z")
    assert p.data["Image"] == "C:\\中文\\a.exe"


def test_sysmon_conversions() -> None:
    pc = sysmon_event(parse_event_xml(evxml(1, 1, {
        "Image": "C:\\Tools\\x.exe", "CommandLine": "x.exe -a", "ProcessId": "100", "ParentProcessId": "4",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "Hashes": "MD5=AA,SHA256=" + "AB" * 32 + ",IMPHASH=CC"})))
    assert pc is not None and pc.kind is EventKind.PROCESS_CREATE and pc.source is EventSource.SYSMON
    assert (pc.process_name, pc.pid, pc.ppid, pc.sha256) == ("x.exe", 100, 4, "ab" * 32)
    assert pc.details["parent_name"] == "WINWORD.EXE"
    net = sysmon_event(parse_event_xml(evxml(2, 3, {"Image": "C:\\a.exe", "ProcessId": "5",
                                                     "DestinationIp": "203.0.113.5", "DestinationPort": "443"})))
    assert net is not None and (net.kind, net.remote_addr, net.remote_port) == (EventKind.NET_CONNECT, "203.0.113.5", 443)
    fc = sysmon_event(parse_event_xml(evxml(3, 11, {"TargetFilename": "C:\\t\\new.exe", "Image": "C:\\b.exe"})))
    assert fc is not None and fc.kind is EventKind.FILE_CREATE and fc.target_path == "C:\\t\\new.exe"
    assert sysmon_event(parse_event_xml(evxml(4, 26, {"TargetFilename": "C:\\t\\d.exe"}))).kind is EventKind.FILE_DELETE  # type: ignore[union-attr]
    assert sysmon_event(parse_event_xml(evxml(5, 99, {}))) is None


def test_security_4688_hex_pids() -> None:
    e = security_event(parse_event_xml(evxml(9, 4688, {
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "NewProcessId": "0x1a2c", "ProcessId": "0x10",
        "CommandLine": "cmd /c echo", "ParentProcessName": "C:\\x\\EXCEL.EXE"})))
    assert e is not None and (e.pid, e.ppid, e.process_name) == (0x1A2C, 0x10, "cmd.exe")
    assert e.details["parent_name"] == "EXCEL.EXE"
    assert security_event(parse_event_xml(evxml(9, 4624, {}))) is None


def test_defender_detection() -> None:
    e = defender_event(parse_event_xml(evxml(7, 1116, {
        "Threat Name": "Virus:DOS/EICAR_Test_File", "Severity Name": "Severe",
        "Path": "file:_C:\\Users\\u\\Downloads\\eicar.com;file:_C:\\other", "Process Name": "Unknown"})))
    assert e is not None and e.kind is EventKind.AV_DETECTION
    assert e.target_path == "C:\\Users\\u\\Downloads\\eicar.com" and e.process_path is None
    assert e.details["threat_name"] == "Virus:DOS/EICAR_Test_File"


# ---------------- event log collector with scripted API ----------------
class ScriptedLog:
    def __init__(self, events: list[str], error: int | None = None) -> None:
        self.events = events
        self.error = error
        self.queries: list[str] = []

    def __call__(self, channel: str, xpath: str = "*", *, reverse: bool = False, max_events: int = 500) -> list[str]:
        self.queries.append(xpath)
        if self.error is not None:
            raise wevt.EventLogError(self.error, "test")
        if reverse:
            return self.events[-1:]
        lo = int(xpath.split("EventRecordID>")[1].split(" ")[0]) if "EventRecordID>" in xpath else 0
        return [x for x in self.events if parse_event_xml(x).record_id > lo][:max_events]


def test_eventlog_collector_cursor_and_self_filter() -> None:
    log = ScriptedLog([evxml(10, 1, {"Image": "C:\\old.exe", "ProcessId": "1"})])
    c = EventLogCollector("t", "ch", EventSource.SYSMON, (1,), sysmon_event, query=log)
    assert c.status().available
    c.start()  # history is not ingested
    log.events += [evxml(11, 1, {"Image": "C:\\new.exe", "ProcessId": "2", "ParentProcessId": "3"}),
                   evxml(12, 1, {"Image": "C:\\Windows\\clamscan.exe", "ProcessId": "9",
                                 "ParentProcessId": str(os.getpid())})]
    evs = c.poll()
    assert [e.process_name for e in evs] == ["new.exe"]  # own child filtered
    assert c.poll() == []  # cursor advanced
    assert "EventRecordID>12" in log.queries[-1]


@pytest.mark.parametrize(("code", "admin", "fragment"), [
    (wevt.ERROR_ACCESS_DENIED, True, "權限"), (wevt.ERROR_EVT_CHANNEL_NOT_FOUND, False, "不存在")])
def test_eventlog_status_mapping(code: int, admin: bool, fragment: str) -> None:
    st = EventLogCollector("t", "ch", EventSource.EVENTLOG, (1,), sysmon_event, query=ScriptedLog([], code)).status()
    assert not st.available and st.requires_admin is admin and fragment in st.detail


def test_folder_watch_coalesce_and_exclude(tmp_path: Path) -> None:
    excluded = tmp_path / "SentinelX"
    c = FolderWatchCollector([tmp_path], exclude=[excluded])
    for _ in range(5):
        c._push(EventKind.FILE_MODIFY, str(tmp_path / "a.txt"), None)
    c._push(EventKind.FILE_CREATE, str(excluded / "db.sqlite"), None)
    c._push(EventKind.FILE_MOVE, str(tmp_path / "a.txt"), str(tmp_path / "b.txt"))
    evs = c.poll()
    assert [(e.kind, Path(e.target_path).name) for e in evs] == [  # type: ignore[arg-type]
        (EventKind.FILE_MODIFY, "a.txt"), (EventKind.FILE_MOVE, "b.txt")]
    assert evs[1].details["from"].endswith("a.txt")


def test_folder_watch_status() -> None:
    assert not FolderWatchCollector([]).status().available
    assert "不存在" in FolderWatchCollector([Path("C:/definitely/missing")]).status().detail


# ---------------- correlation ----------------
def ev(i: int, kind: EventKind, **kw) -> StoredEvent:  # type: ignore[no-untyped-def]
    base = dict(source=EventSource.PSUTIL, kind=kind, occurred_at="2026-11-02T07:00:00Z")
    base.update(kw)
    return StoredEvent(**base, id=i)  # type: ignore[arg-type]


THREAT = "C:\\Users\\u\\Downloads\\bad.exe"


def index(cls: Classification = Classification.CONFIRMED_THREAT, quarantined: bool = False) -> ThreatIndex:
    i = ThreatIndex()
    i.by_path[norm_path(THREAT)] = ThreatInfo(cls, 7, quarantined)
    i.by_sha["f" * 64] = ThreatInfo(cls, 7, quarantined)
    return i


def correlate(events: list[StoredEvent], idx: ThreatIndex | None = None, staging: list[str] | None = None):  # type: ignore[no-untyped-def]
    return Correlator(staging if staging is not None else [norm_path("C:\\Users\\u\\Downloads")]).process(
        events, idx or ThreatIndex())


def test_R1_threat_executed_by_path_and_hash() -> None:
    [a] = correlate([ev(1, EventKind.PROCESS_CREATE, process_path=THREAT.upper(), pid=5)], index())
    assert a.rule_id == "R1_THREAT_EXECUTED" and a.severity is Severity.HIGH
    assert any("判定 #7" in f for f in a.observed_facts) and any("事件 #1" in f for f in a.observed_facts)
    [b] = correlate([ev(2, EventKind.PROCESS_CREATE, process_path="C:\\other\\x.exe", sha256="f" * 64)],
                    index(Classification.SUSPICIOUS))
    assert b.severity is Severity.MEDIUM and "可疑" in b.title


def test_R2_quarantined_path_rewritten() -> None:
    [a] = correlate([ev(1, EventKind.FILE_CREATE, target_path=THREAT)], index(quarantined=True))
    assert a.rule_id == "R2_THREAT_PATH_WRITTEN" and "隔離" in a.title
    assert correlate([ev(1, EventKind.FILE_CREATE, target_path=THREAT)], index(Classification.SUSPICIOUS)) == []


def test_R2_running_a_threat_is_not_reported_as_modification() -> None:
    """Executing a file makes Windows report FILE_MODIFY (access time); that alone is not a rewrite."""
    assert correlate([ev(1, EventKind.FILE_MODIFY, target_path=THREAT)], index()) == []
    [a] = correlate([ev(2, EventKind.FILE_CREATE, target_path=THREAT)], index())
    assert a.severity is Severity.LOW
    [q] = correlate([ev(3, EventKind.FILE_MODIFY, target_path=THREAT)], index(quarantined=True))
    assert q.severity is Severity.MEDIUM


@pytest.mark.parametrize(("cmd", "hit"), [
    ("powershell.exe -NoProfile -EncodedCommand SQBFAFgA", True),
    ("powershell -enc SQBFAFgA", True), ("powershell /e SQBFAFgA", True), ("pwsh -ec SQBF", True),
    ("powershell -ExecutionPolicy Bypass -File x.ps1", False), ("powershell -Command Get-Date", False),
])
def test_R3_encoded_powershell(cmd: str, hit: bool) -> None:
    assert has_encoded_command(cmd) is hit
    alerts = correlate([ev(1, EventKind.PROCESS_CREATE, process_name="powershell.exe", command_line=cmd)])
    assert bool(alerts) is hit


def test_R4_office_spawns_shell() -> None:
    e = ev(1, EventKind.PROCESS_CREATE, process_name="cmd.exe", pid=9, ppid=8,
           details={"parent_name": "WINWORD.EXE", "parent_image": "C:\\Office\\WINWORD.EXE"})
    [a] = correlate([e])
    assert a.rule_id == "R4_OFFICE_SPAWNS_SHELL"
    assert correlate([ev(1, EventKind.PROCESS_CREATE, process_name="notepad.exe",
                         details={"parent_name": "WINWORD.EXE"})]) == []


def test_R5_staged_program_network_within_window() -> None:
    c = Correlator([norm_path("C:\\Users\\u\\Downloads")])
    start = ev(1, EventKind.PROCESS_CREATE, process_path="C:\\Users\\u\\Downloads\\setup.exe", pid=33)
    assert c.process([start], ThreatIndex()) == []
    [a] = c.process([ev(2, EventKind.NET_CONNECT, pid=33, remote_addr="198.51.100.7", remote_port=443,
                        occurred_at="2026-11-02T07:01:00Z")], ThreatIndex())
    assert a.rule_id == "R5_TEMP_PROGRAM_NETWORK" and a.event_ids == [1, 2] and a.severity is Severity.LOW
    late = ev(3, EventKind.NET_CONNECT, pid=33, remote_addr="x", occurred_at="2026-11-02T07:10:00Z")
    assert c.process([late], ThreatIndex()) == []


def test_R6_av_detection_compares_with_own_verdict() -> None:
    d = ev(1, EventKind.AV_DETECTION, source=EventSource.EVENTLOG, target_path=THREAT, raw_ref="Defender:5",
           details={"threat_name": "Virus:DOS/EICAR_Test_File", "severity": "Severe"})
    [a] = correlate([d], index())
    assert "EICAR" in a.title and any("Sentinel X 對同一檔案" in f for f in a.observed_facts)
    [b] = correlate([d])
    assert any("沒有這個檔案的判定" in f for f in b.observed_facts)


def test_facts_and_analysis_are_separate() -> None:
    alerts = correlate([
        ev(1, EventKind.PROCESS_CREATE, process_path=THREAT, pid=5),
        ev(2, EventKind.PROCESS_CREATE, process_name="powershell.exe", command_line="powershell -enc AAA"),
    ], index())
    for a in alerts:
        assert a.analysis and a.observed_facts
        for f in a.observed_facts:
            assert a.analysis not in f
            assert not any(w in f for w in ("可能", "建議", "常見"))  # interpretation words stay in analysis


def test_no_alert_for_ordinary_activity() -> None:
    assert correlate([
        ev(1, EventKind.PROCESS_CREATE, process_path="C:\\Windows\\System32\\notepad.exe", pid=1),
        ev(2, EventKind.NET_CONNECT, pid=1, remote_addr="203.0.113.1", remote_port=443),
        ev(3, EventKind.FILE_MODIFY, target_path="C:\\Users\\u\\Documents\\a.docx"),
    ]) == []


# ---------------- elevation / config ----------------
def test_elevation_command_is_fixed() -> None:
    assert elevation_command("C:\\py\\python.exe", False) == ("C:\\py\\python.exe", "-m sentinelx --elevated")
    assert elevation_command("C:\\SX\\SentinelX.exe", True) == ("C:\\SX\\SentinelX.exe", "--elevated")


def test_monitor_settings_validation() -> None:
    with pytest.raises(ValueError):
        MonitorSettings(watch_dirs=["relative\\dir"])
    with pytest.raises(ValueError):
        MonitorSettings(poll_interval_s=0.1)
    assert MonitorSettings(watch_dirs=["C:\\Data"]).watch_dirs == ["C:\\Data"]
