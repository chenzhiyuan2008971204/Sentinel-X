"""Correlation rules. Every alert separates:

  observed_facts  - what the collectors recorded and what Sentinel X's database says,
                    stated without interpretation;
  analysis        - what it might mean, including the innocent explanations.

Alerts never trigger any action. Rules:

  R1 THREAT_EXECUTED        a process started from a file whose latest verdict is
                            CONFIRMED_THREAT / SUSPICIOUS (by path or SHA-256).
  R2 THREAT_PATH_WRITTEN    a file was written at the path of a quarantined or confirmed threat.
  R3 ENCODED_POWERSHELL     PowerShell started with an encoded command.
  R4 OFFICE_SPAWNS_SHELL    an Office application started a shell or script host.
  R5 TEMP_PROGRAM_NETWORK   a program started from Temp/Downloads opened a network
                            connection within two minutes.
  R6 AV_DETECTION           another product (Defender) reported a detection; compared with
                            Sentinel X's own verdict for the same file.
"""

from __future__ import annotations

import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinelx.core.enums import Classification, Severity
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.monitor.events import KIND_TEXT, EventKind, StoredEvent
from sentinelx.scanner.exclusions import norm_path
from sentinelx.storage.event_repository import AlertIn

OFFICE = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"})
SHELLS = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "rundll32.exe", "regsvr32.exe"})
NET_WINDOW = timedelta(minutes=2)


def has_encoded_command(command_line: str) -> bool:
    """PowerShell accepts any prefix of -EncodedCommand (and -ec), with - or / ."""
    for tok in re.split(r"\s+", command_line):
        t = tok.lower()
        if len(t) >= 2 and t[0] in "-/":
            word = t[1:]
            if word == "ec" or "encodedcommand".startswith(word):
                return True
    return False


@dataclass(frozen=True)
class ThreatInfo:
    classification: Classification
    verdict_id: int
    quarantined: bool = False


@dataclass
class ThreatIndex:
    by_path: dict[str, ThreatInfo] = field(default_factory=dict)  # norm_path -> info
    by_sha: dict[str, ThreatInfo] = field(default_factory=dict)

    def lookup(self, path: str | None, sha: str | None) -> ThreatInfo | None:
        if path and (hit := self.by_path.get(norm_path(path))):
            return hit
        if sha and (hit := self.by_sha.get(sha.lower())):
            return hit
        return None


def user_staging_dirs() -> list[str]:
    dirs = []
    for d in (os.environ.get("TEMP"), os.environ.get("TMP"), str(Path.home() / "Downloads")):
        if d:
            dirs.append(norm_path(d))
    return dirs


def _under(path: str | None, roots: list[str]) -> bool:
    if not path:
        return False
    n = norm_path(path)
    return any(n.startswith(r + os.sep) for r in roots)


def _parse(t: str) -> datetime:
    try:
        return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)


def _fact(e: StoredEvent) -> str:
    parts = [f"{e.occurred_at} {KIND_TEXT[e.kind]}（{e.source.value}，事件 #{e.id}）"]
    if e.process_path or e.process_name:
        parts.append(f"程序 {e.process_path or e.process_name}" + (f"（PID {e.pid}）" if e.pid else ""))
    if e.command_line:
        cl = e.command_line if len(e.command_line) <= 300 else e.command_line[:300] + "…"
        parts.append(f"命令列：{cl}")
    if e.target_path:
        parts.append(f"檔案：{e.target_path}")
    if e.remote_addr:
        parts.append(f"遠端：{e.remote_addr}:{e.remote_port}")
    return "；".join(parts)


class Correlator:
    def __init__(self, staging_dirs: list[str] | None = None) -> None:
        self._staging = staging_dirs if staging_dirs is not None else user_staging_dirs()
        self._recent_staged: OrderedDict[int, StoredEvent] = OrderedDict()  # pid -> PROCESS_CREATE

    def process(self, events: list[StoredEvent], index: ThreatIndex) -> list[AlertIn]:
        alerts: list[AlertIn] = []
        for e in events:
            if e.kind is EventKind.PROCESS_CREATE:
                alerts += self._threat_executed(e, index)
                alerts += self._encoded_powershell(e)
                alerts += self._office_shell(e)
                if e.pid and _under(e.process_path, self._staging):
                    self._recent_staged[e.pid] = e
                    while len(self._recent_staged) > 5000:
                        self._recent_staged.popitem(last=False)
            elif e.kind in (EventKind.FILE_CREATE, EventKind.FILE_MODIFY, EventKind.FILE_MOVE):
                alerts += self._threat_path_written(e, index)
            elif e.kind is EventKind.NET_CONNECT:
                alerts += self._staged_network(e)
            elif e.kind is EventKind.AV_DETECTION:
                alerts += self._av_detection(e, index)
        return alerts

    # R1
    def _threat_executed(self, e: StoredEvent, index: ThreatIndex) -> list[AlertIn]:
        hit = index.lookup(e.process_path, e.sha256)
        if hit is None or hit.classification not in (Classification.CONFIRMED_THREAT, Classification.SUSPICIOUS):
            return []
        confirmed = hit.classification is Classification.CONFIRMED_THREAT
        return [AlertIn(
            "R1_THREAT_EXECUTED", "已判定為威脅的檔案被執行" if confirmed else "可疑檔案被執行",
            Severity.HIGH if confirmed else Severity.MEDIUM,
            [_fact(e), f"Sentinel X 對此檔案的最新判定：{CLASS_TEXT[hit.classification]}（判定 #{hit.verdict_id}）"],
            "被判定為威脅（或可疑）的檔案正在執行。可能是使用者自行開啟，也可能由其他程式啟動。"
            "Sentinel X 不會終止程序；請判斷是否需要結束程式、隔離檔案或進一步調查。"
            + ("" if confirmed else "此檔案只是「可疑」，尚未確認為惡意。"),
            [e.id], f"R1:{norm_path(e.process_path or '')}:{e.pid}",
        )]

    # R2
    def _threat_path_written(self, e: StoredEvent, index: ThreatIndex) -> list[AlertIn]:
        hit = index.lookup(e.target_path, None)
        if hit is None:
            return []
        if hit.quarantined:
            # The path should be empty after quarantine, so any write there is notable.
            title, sev = "已隔離檔案的原位置又出現檔案", Severity.MEDIUM
            analysis = ("被隔離的威脅檔案原本的位置出現了新的寫入。可能是使用者重新下載、程式重新產生同名檔案，"
                        "或惡意程式試圖還原自己。建議重新掃描該檔案。")
        elif hit.classification is Classification.CONFIRMED_THREAT and e.kind is not EventKind.FILE_MODIFY:
            # FILE_MODIFY is not used here: Windows also reports it when a file is merely run or
            # read (access time / attributes), which would turn every execution into an alert.
            title, sev = "已知威脅的路徑出現新檔案", Severity.LOW
            analysis = "已判定為威脅的檔案位置被新建或移入檔案，先前的判定可能已不適用，建議重新掃描。"
        else:
            return []
        return [AlertIn("R2_THREAT_PATH_WRITTEN", title, sev,
                        [_fact(e), f"此路徑的最新判定：{CLASS_TEXT[hit.classification]}（判定 #{hit.verdict_id}）"
                         + ("，且已被隔離" if hit.quarantined else "")],
                        analysis, [e.id], f"R2:{norm_path(e.target_path or '')}")]

    # R3
    @staticmethod
    def _encoded_powershell(e: StoredEvent) -> list[AlertIn]:
        name = (e.process_name or "").lower()
        if name not in ("powershell.exe", "pwsh.exe") or not e.command_line or not has_encoded_command(e.command_line):
            return []
        return [AlertIn("R3_ENCODED_POWERSHELL", "PowerShell 以編碼指令執行", Severity.MEDIUM, [_fact(e)],
                        "使用 -EncodedCommand 會讓實際執行的指令不易閱讀，常被用來隱藏惡意行為；"
                        "但部分管理工具與安裝程式也會使用。可將命令列中的 Base64 解碼後確認內容。",
                        [e.id], f"R3:{e.pid}:{e.occurred_at}")]

    # R4
    @staticmethod
    def _office_shell(e: StoredEvent) -> list[AlertIn]:
        parent = str(e.details.get("parent_name") or "").lower()
        child = (e.process_name or "").lower()
        if parent not in OFFICE or child not in SHELLS:
            return []
        return [AlertIn("R4_OFFICE_SPAWNS_SHELL", "Office 程式啟動了命令列或指令碼程式", Severity.MEDIUM,
                        [_fact(e), f"父程序：{e.details.get('parent_image') or parent}（PID {e.ppid}）"],
                        "Office 文件透過巨集啟動 PowerShell、cmd 等程式是常見的惡意文件手法；"
                        "也可能是公司內部的合法巨集或增益集。請確認剛開啟的文件來源。",
                        [e.id], f"R4:{e.ppid}:{e.pid}")]

    # R5
    def _staged_network(self, e: StoredEvent) -> list[AlertIn]:
        if not e.pid or e.pid not in self._recent_staged:
            return []
        start = self._recent_staged[e.pid]
        if abs(_parse(e.occurred_at) - _parse(start.occurred_at)) > NET_WINDOW:
            return []
        return [AlertIn("R5_TEMP_PROGRAM_NETWORK", "暫存或下載資料夾中的程式建立網路連線", Severity.LOW,
                        [_fact(start), _fact(e)],
                        "從暫存或下載資料夾直接執行的程式在啟動後很快連上網路。安裝程式、更新程式常有這種行為，"
                        "下載器型的惡意程式也是。若不認得這個程式，建議掃描它。",
                        [start.id, e.id], f"R5:{e.pid}:{start.occurred_at}")]

    # R6
    @staticmethod
    def _av_detection(e: StoredEvent, index: ThreatIndex) -> list[AlertIn]:
        hit = index.lookup(e.target_path, None)
        threat = e.details.get("threat_name") or "未知"
        ours = (f"Sentinel X 對同一檔案的最新判定：{CLASS_TEXT[hit.classification]}（判定 #{hit.verdict_id}）"
                if hit else "Sentinel X 沒有這個檔案的判定（尚未掃描，或判定為未發現威脅）")
        action = e.details.get("action")
        return [AlertIn("R6_AV_DETECTION", f"Microsoft Defender 偵測到 {threat}", Severity.MEDIUM,
                        [_fact(e), f"Defender 威脅名稱：{threat}；嚴重性：{e.details.get('severity') or '未提供'}"
                         + (f"；動作：{action}" if action else ""), ours],
                        "另一個防毒產品對此檔案提出偵測。兩個獨立產品結果一致時可信度較高；"
                        "若 Sentinel X 沒有相同判定，可在掃描中心掃描此檔案比對。Defender 的處置由 Defender 自行執行，與 Sentinel X 無關。",
                        [e.id], f"R6:{e.raw_ref or e.id}")]
