"""Turn a trial-run report into standard evidence (engine "Sandbox").

What counts, and how strongly (graded in core/risk.py from evidence["strength"]):
  strong    the VM's own Windows Defender detected a threat; 10+ decoy documents were changed or
            deleted (ransomware-like); the sample turned off Defender's real-time protection
  moderate  new autostart entry (Run key, startup folder, service, scheduled task, WMI consumer);
            hosts file changed
  weak      new executable files dropped; outbound connection attempts (the VM has no network)
Nothing observed is reported as "no suspicious behaviour seen", never as safe: samples can
notice a VM and stay quiet, or wait longer than the observation time.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget

ENGINE_NAME = "Sandbox"
ENGINE_VERSION = "1.0"
_SEV = {"strong": Severity.HIGH, "moderate": Severity.MEDIUM, "weak": Severity.LOW}
DECOY_THRESHOLD = 10


def findings(rep: dict[str, Any]) -> list[tuple[str, str, str, dict[str, Any]]]:
    """(rule_id, strength, plain explanation, evidence) for each suspicious behaviour."""
    out: list[tuple[str, str, str, dict[str, Any]]] = []
    if int(rep.get("defender_new_detections") or 0) > 0:
        names = rep.get("defender_threat_names") or []
        out.append(("Sandbox.DefenderDetected", "strong",
                    "試跑時，虛擬機裡的 Windows Defender 偵測到威脅" + (f"（{names[0]}）" if names else "") + "。",
                    {"threat_names": names}))
    changed, total = int(rep.get("decoys_changed") or 0), int(rep.get("decoys_total") or 0)
    if changed >= DECOY_THRESHOLD:
        out.append(("Sandbox.DecoysModified", "strong",
                    f"像勒索病毒：{total} 份誘餌文件中有 {changed} 份被改動、加密或刪除。", {"changed": changed, "total": total}))
    if rep.get("defender_disabled"):
        out.append(("Sandbox.DefenderDisabled", "strong", "它把虛擬機裡 Windows Defender 的即時防護關掉了。", {}))
    pers = rep.get("persistence") or {}
    kinds = {"run_keys": "開機自動執行的登錄項目", "startup": "啟動資料夾", "services": "系統服務",
             "tasks": "排程工作", "wmi": "WMI 事件訂閱"}
    for k, label in kinds.items():
        items = [i for i in (pers.get(k) or []) if i]
        if items:
            out.append((f"Sandbox.Persistence.{k}", "moderate", f"它新增了{label}，讓自己開機後自動執行。",
                        {"items": items[:10]}))
    if rep.get("hosts_changed"):
        out.append(("Sandbox.HostsChanged", "moderate", "它修改了 hosts 檔（可能把網址導到假網站）。", {}))
    exes = [f for f in (rep.get("dropped_executables") or []) if f]
    if exes:
        out.append(("Sandbox.DroppedExecutables", "weak", f"它在電腦裡放了 {len(exes)} 個新的程式或腳本檔。",
                    {"files": exes[:15]}))
    net = [n for n in (rep.get("network_attempts") or []) if n]
    if net:
        out.append(("Sandbox.NetworkAttempts", "weak", f"它嘗試連線到 {len(net)} 個網路位址（虛擬機沒有網路，所以沒有連上）。",
                    {"destinations": net[:15]}))
    return out


class SandboxEngine:
    """Not part of normal scans (a run takes minutes); used only for trial runs the user starts."""

    name = ENGINE_NAME

    def __init__(self, run: Callable[[Path, CancelToken], dict[str, Any]], seconds: int) -> None:
        self._run = run
        self._seconds = seconds
        self.last_report: dict[str, Any] | None = None

    def availability(self, refresh: bool = False) -> EngineStatus:
        return EngineStatus(ENGINE_NAME, True, version=ENGINE_VERSION, detail="在虛擬機中試跑並觀察行為",
                            detection_capable=False)  # quiet behaviour never proves a file clean

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        out: dict[ScanTarget, DetectionResult] = {}
        for t in targets:
            rep = self._run(t.path, cancel)
            self.last_report = rep
            info = {"started": bool(rep.get("started")), "start_error": rep.get("start_error"),
                    "seconds": self._seconds, "processes": [p.get("name") for p in rep.get("processes") or []][:20],
                    "detection_capable": False}
            dets = tuple(
                DetectionRecord(engine_name=ENGINE_NAME, engine_version=ENGINE_VERSION, rule_id=rule,
                                severity_hint=_SEV[strength], evidence=dict(ev, strength=strength,
                                                                            observed_seconds=self._seconds),
                                file_sha256=t.sha256, confidence_explanation=text + "這是在隔離的虛擬機裡觀察到的行為。")
                for rule, strength, text, ev in findings(rep))
            kind = EngineOutcomeKind.FINDINGS if dets else EngineOutcomeKind.NO_FINDINGS
            out[t] = DetectionResult(engine_name=ENGINE_NAME, kind=kind, engine_version=ENGINE_VERSION,
                                     detections=dets, info=info)
        return out
