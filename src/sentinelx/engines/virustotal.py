"""VirusTotal hash reputation: what about 70 antivirus engines (and public sandbox runs) say
about a file, looked up by its SHA-256.

Privacy: only the SHA-256 is sent (GET /api/v3/files/{sha256}); the file itself is never
uploaded. Used only after the user agreed and stored an API key.

Free public API: 4 lookups per minute and 500 per day. Results are cached (3 days for known
files, 1 day for files VirusTotal has not seen). When the limit is reached, a file is SKIPPED
with the reason, never marked unclean or unassessed: this engine adds evidence, it is never
required for a scan to be complete.

Outcome per file:
- not a type worth looking up (text, images, ...)       -> SKIPPED
- no key / no consent / quota / network error           -> SKIPPED (reason in info)
- VirusTotal has never seen it                          -> NO_FINDINGS, info.found = False
- seen, no engine says malicious                        -> NO_FINDINGS with the counts
- seen, N engines say malicious                         -> FINDINGS, severity by N
  (graded in core/risk.py: 10+ strong, 3-9 moderate, 1-2 weak)
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.db import Database
from sentinelx.storage.orm import VtReport

log = logging.getLogger(__name__)

ENGINE_NAME = "VirusTotal"
ENGINE_VERSION = "1.0"
API_BASE = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"
PER_MINUTE = 4
PER_DAY = 500
REALTIME_DAILY_CAP = 350  # real-time protection leaves the rest of the day's lookups to manual scans
MAX_WAIT_PER_BATCH_S = 20.0  # wait at most this long for the per-minute limit, then skip
CACHE_FOUND = timedelta(days=3)
CACHE_NOT_FOUND = timedelta(days=1)
STALE_ANALYSIS = timedelta(days=180)  # older "0 detections" results do not count as a check (audit 8, L4)
TIMEOUT_S = 20
TS = "%Y-%m-%dT%H:%M:%SZ"
LOOKUP_SUFFIXES = frozenset({
    ".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".pif", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".apk",
    ".zip", ".rar", ".7z", ".iso", ".img", ".cab",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf", ".rtf",
})
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _stale(last_analysis: str | None) -> bool:
    """True when VirusTotal last analysed the file long ago (or the date is unknown)."""
    if not last_analysis:
        return True
    try:
        when = datetime.strptime(last_analysis, TS).replace(tzinfo=UTC)
    except ValueError:
        return True
    return datetime.now(UTC) - when > STALE_ANALYSIS


class VtError(Exception):
    """A lookup could not be made; `reason` is shown to the user (zh-TW)."""

    def __init__(self, reason: str, *, fatal: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fatal = fatal  # wrong key: stop trying for this batch


def worth_looking_up(path: Path) -> bool:
    if path.suffix.lower() in LOOKUP_SUFFIXES:
        return True
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"  # programs without the usual extension
    except OSError:
        return False


def parse_report(sha256: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize a /files response (None = not found) to the cached fields."""
    if payload is None:
        return {"sha256": sha256, "found": 0, "malicious": 0, "suspicious": 0, "engines_total": 0,
                "threat_label": None, "names": [], "sandbox_malicious": 0, "last_analysis": None}
    a = (payload.get("data") or {}).get("attributes") or {}
    stats = a.get("last_analysis_stats") or {}
    results = a.get("last_analysis_results") or {}
    names = sorted(f"{eng}: {r.get('result')}" for eng, r in results.items()
                   if isinstance(r, dict) and r.get("category") == "malicious" and r.get("result"))
    counted = ("malicious", "suspicious", "undetected", "harmless")
    sandboxes = a.get("sandbox_verdicts") or {}
    label = ((a.get("popular_threat_classification") or {}).get("suggested_threat_label"))
    when = a.get("last_analysis_date")
    return {
        "sha256": sha256, "found": 1,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "engines_total": sum(int(stats.get(k, 0) or 0) for k in counted),
        "threat_label": str(label) if label else None,
        "names": names[:12],
        "sandbox_malicious": sum(1 for v in sandboxes.values() if isinstance(v, dict) and v.get("category") == "malicious"),
        "last_analysis": datetime.fromtimestamp(int(when), UTC).strftime(TS) if when else None,
    }


class VtClient:
    """HTTP access to the VirusTotal API, with the free-tier limits applied locally."""

    def __init__(self, key: Callable[[], str | None], *, base: str = API_BASE, quota_file: Path | None = None,
                 per_minute: int = PER_MINUTE, per_day: int = PER_DAY,
                 opener: Callable[..., Any] = urllib.request.urlopen, clock: Callable[[], float] = time.monotonic,
                 utc_now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._key = key
        self._base = base.rstrip("/")
        self._quota_file = quota_file
        self._per_minute = per_minute
        self._per_day = per_day
        self._open = opener
        self._clock = clock
        self._utc_now = utc_now
        self._recent: deque[float] = deque()
        self._lock = threading.Lock()

    # ---- limits ----
    def _day_count(self) -> tuple[str, int]:
        # VirusTotal's daily quota resets at 00:00 UTC (08:00 in Taiwan), not at local midnight.
        today = self._utc_now().date().isoformat()
        if self._quota_file is None:
            return today, 0
        try:
            d = json.loads(self._quota_file.read_text(encoding="utf-8"))
            return today, int(d.get("count", 0)) if d.get("day") == today else 0
        except (OSError, ValueError, TypeError):
            return today, 0

    def _count_day(self) -> None:
        if self._quota_file is None:
            return
        today, n = self._day_count()
        tmp = self._quota_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"day": today, "count": n + 1}), encoding="utf-8")
        tmp.replace(self._quota_file)

    def used_today(self) -> int:
        return self._day_count()[1]

    def wait_needed(self) -> float:
        """Seconds until a lookup is allowed by the per-minute limit (0 = now)."""
        with self._lock:
            now = self._clock()
            while self._recent and now - self._recent[0] >= 60:
                self._recent.popleft()
            return 0.0 if len(self._recent) < self._per_minute else 60 - (now - self._recent[0])

    # ---- lookup ----
    def lookup(self, sha256: str) -> dict[str, Any] | None:
        """Raw /files report, or None if VirusTotal has not seen the file. Raises VtError."""
        key = self._key()
        if not key:
            raise VtError("尚未設定 VirusTotal API 金鑰", fatal=True)
        if self.used_today() >= self._per_day:
            raise VtError(f"今天的 VirusTotal 免費查詢次數（{self._per_day} 次）已用完")
        if self.wait_needed() > 0:
            raise VtError("已達每分鐘查詢上限（免費版每分鐘 4 次）")
        with self._lock:
            self._recent.append(self._clock())
        self._count_day()
        req = urllib.request.Request(f"{self._base}/files/{sha256}", headers={"x-apikey": key, "accept": "application/json"})
        try:
            with self._open(req, timeout=TIMEOUT_S) as resp:
                return json.loads(resp.read(8 * 1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code in (401, 403):
                raise VtError("VirusTotal 拒絕了 API 金鑰（金鑰錯誤或已停用）", fatal=True) from exc
            if exc.code == 429:
                raise VtError("VirusTotal 回報查詢次數超過上限，稍後再試") from exc
            raise VtError(f"VirusTotal 回應錯誤（HTTP {exc.code}）") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise VtError("無法連線到 VirusTotal（網路問題）") from exc
        except ValueError as exc:
            raise VtError("VirusTotal 回應格式無法解讀") from exc


class VirusTotalEngine:
    name = ENGINE_NAME

    def __init__(self, db: Database, client: VtClient, enabled: Callable[[], bool],
                 *, max_wait_s: float = MAX_WAIT_PER_BATCH_S) -> None:
        self._db = db
        self._client = client
        self._enabled = enabled  # consent given and a key stored
        self._max_wait = max_wait_s

    def availability(self, refresh: bool = False) -> EngineStatus:
        if not self._enabled():
            return EngineStatus(ENGINE_NAME, False, version=ENGINE_VERSION,
                                detail="VirusTotal 查詢未啟用（需要在設定中同意並輸入 API 金鑰）")
        used = self._client.used_today()
        return EngineStatus(ENGINE_NAME, True, version=ENGINE_VERSION, rules_version="API v3",
                            detail=f"只送出 SHA-256 查詢，不上傳檔案；今天已查詢 {used}/{PER_DAY} 次",
                            detection_capable=True)

    # ---- cache ----
    def cached(self, sha256: str, now: datetime | None = None) -> dict[str, Any] | None:
        now = now or datetime.now(UTC)
        with self._db.session() as s:
            r = s.get(VtReport, sha256)
            if r is None:
                return None
            age = now - datetime.strptime(r.fetched_at, TS).replace(tzinfo=UTC)
            if age > (CACHE_FOUND if r.found else CACHE_NOT_FOUND):
                return None
            return {"sha256": r.sha256, "found": r.found, "malicious": r.malicious, "suspicious": r.suspicious,
                    "engines_total": r.engines_total, "threat_label": r.threat_label,
                    "names": json.loads(r.names_json or "[]"), "sandbox_malicious": r.sandbox_malicious,
                    "last_analysis": r.last_analysis, "fetched_at": r.fetched_at}

    def _store(self, rep: dict[str, Any]) -> dict[str, Any]:
        rep = dict(rep, fetched_at=utc_now_iso())
        with self._db.session() as s:
            row = s.get(VtReport, rep["sha256"]) or VtReport(sha256=rep["sha256"])
            row.found, row.malicious, row.suspicious = rep["found"], rep["malicious"], rep["suspicious"]
            row.engines_total, row.threat_label = rep["engines_total"], rep["threat_label"]
            row.names_json = json.dumps(rep["names"], ensure_ascii=False)
            row.sandbox_malicious, row.last_analysis, row.fetched_at = rep["sandbox_malicious"], rep["last_analysis"], rep["fetched_at"]
            s.merge(row)
        return rep

    def report(self, sha256: str, *, use_cache: bool = True) -> dict[str, Any]:
        """Cached or fresh report for one hash (Research Lab, tests). Raises VtError."""
        sha256 = sha256.lower()
        if use_cache and (c := self.cached(sha256)) is not None:
            return dict(c, from_cache=True)
        return dict(self._store(parse_report(sha256, self._client.lookup(sha256))), from_cache=False)

    # ---- engine ----
    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken, *,
                   max_wait_s: float | None = None) -> dict[ScanTarget, DetectionResult]:
        out: dict[ScanTarget, DetectionResult] = {}
        max_wait = self._max_wait if max_wait_s is None else max_wait_s
        waited = 0.0
        stop_reason: str | None = None
        for t in targets:
            cancel.raise_if_cancelled()
            started = time.monotonic()
            if not worth_looking_up(t.path):
                out[t] = self._result(EngineOutcomeKind.SKIPPED, info={"skip_reason": "此檔案類型不查詢"})
                continue
            rep = self.cached(t.sha256)
            if rep is None and stop_reason is None:
                need = self._client.wait_needed()
                if need > 0 and waited + need <= max_wait:
                    end = time.monotonic() + need
                    while time.monotonic() < end:
                        cancel.raise_if_cancelled()
                        time.sleep(min(0.2, max(0.0, end - time.monotonic())))
                    waited += need
                try:
                    rep = self._store(parse_report(t.sha256, self._client.lookup(t.sha256)))
                except VtError as exc:
                    if exc.fatal or "上限" in exc.reason or "用完" in exc.reason:
                        stop_reason = exc.reason
                    out[t] = self._result(EngineOutcomeKind.SKIPPED, info={"skip_reason": exc.reason})
                    continue
            if rep is None:
                out[t] = self._result(EngineOutcomeKind.SKIPPED, info={"skip_reason": stop_reason or "未查詢"})
                continue
            out[t] = self._from_report(t, rep, int((time.monotonic() - started) * 1000))
        return out

    def _result(self, kind: EngineOutcomeKind, *, info: dict[str, Any], detections: tuple[DetectionRecord, ...] = (),
                ms: int = 0) -> DetectionResult:
        return DetectionResult(engine_name=ENGINE_NAME, kind=kind, engine_version=ENGINE_VERSION,
                               rules_version="API v3", detections=detections, duration_ms=ms, info=info)

    def _from_report(self, t: ScanTarget, rep: dict[str, Any], ms: int) -> DetectionResult:
        info = {"found": bool(rep["found"]), "malicious": rep["malicious"], "suspicious": rep["suspicious"],
                "engines_total": rep["engines_total"], "threat_label": rep["threat_label"],
                "sandbox_malicious": rep["sandbox_malicious"], "last_analysis": rep["last_analysis"],
                "detection_capable": bool(rep["found"]) and rep["engines_total"] > 0 and not _stale(rep["last_analysis"]),
                "link": GUI_URL.format(sha256=t.sha256)}
        m = rep["malicious"]
        if not rep["found"] or m == 0:
            return self._result(EngineOutcomeKind.NO_FINDINGS, info=info, ms=ms)
        severity = Severity.HIGH if m >= 10 else (Severity.MEDIUM if m >= 3 else Severity.LOW)
        label = f"（常見名稱：{rep['threat_label']}）" if rep["threat_label"] else ""
        text = (f"VirusTotal 上 {rep['engines_total']} 家防毒引擎中有 {m} 家判定為惡意{label}"
                f"；最近一次分析：{rep['last_analysis'] or '不明'}。這是其他廠商的判斷，"
                "家數越多越可靠；只有 1～2 家時常是誤判。只送出 SHA-256 查詢，檔案沒有上傳。")
        d = DetectionRecord(
            engine_name=ENGINE_NAME, engine_version=ENGINE_VERSION, rule_id="VirusTotal.consensus",
            severity_hint=severity,
            evidence={"malicious": m, "suspicious": rep["suspicious"], "engines_total": rep["engines_total"],
                      "threat_label": rep["threat_label"], "detections": rep["names"],
                      "sandbox_malicious": rep["sandbox_malicious"], "last_analysis": rep["last_analysis"],
                      "fetched_at": rep.get("fetched_at"), "link": info["link"]},
            file_sha256=t.sha256, confidence_explanation=text)
        return self._result(EngineOutcomeKind.FINDINGS, info=info, detections=(d,), ms=ms)


class RealtimeVirusTotal:
    """VirusTotal as real-time protection uses it (engineering audit 8, M2).

    The free tier allows 4 lookups a minute and 500 a day. Watching whole drives, installers and
    Windows updates create many programs and documents; asking about all of them used up the
    day's lookups and made real-time scans wait up to 20 s per batch. Here only files in the
    places where people bring in files (Downloads, Desktop, Documents, USB drives: `wanted`) are
    looked up, never with waiting, and at most REALTIME_DAILY_CAP a day."""

    name = ENGINE_NAME

    def __init__(self, inner: VirusTotalEngine, wanted: Callable[[Path], bool], *, cap: int = REALTIME_DAILY_CAP) -> None:
        self._inner = inner
        self._wanted = wanted
        self._cap = cap

    def availability(self, refresh: bool = False) -> EngineStatus:
        return self._inner.availability(refresh)

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        out: dict[ScanTarget, DetectionResult] = {}
        ask: list[ScanTarget] = []
        over_cap = self._inner._client.used_today() >= self._cap
        for t in targets:
            if not self._wanted(t.path):
                reason = "即時防護只對下載、桌面、文件與 USB 裡的檔案查詢 VirusTotal"
            elif over_cap and self._inner.cached(t.sha256) is None:
                reason = f"即時防護今天已用了 {self._cap} 次 VirusTotal 查詢，其餘留給手動掃描"
            else:
                ask.append(t)
                continue
            out[t] = self._inner._result(EngineOutcomeKind.SKIPPED, info={"skip_reason": reason})
        if ask:
            out.update(self._inner.scan_batch(ask, cancel, max_wait_s=0.0))
        return out
