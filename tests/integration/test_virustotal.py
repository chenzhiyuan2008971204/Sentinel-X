"""0.15.0: VirusTotal hash lookups, against a fake API (never the network)."""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from fakes import FakeEngine
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import Classification, EngineOutcomeKind
from sentinelx.core.models import ScanTarget
from sentinelx.core.risk import Reliability, assess, grade
from sentinelx.core.secret_store import SecretFile
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.virustotal import EICAR_SHA256, VirusTotalEngine, VtClient, parse_report
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.hashing import sha256_file
from sentinelx.scanner.orchestrator import ScanOrchestrator
from sentinelx.storage.db import Database
from sentinelx.storage.scan_repository import ScanRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
KEY = "a" * 64


def payload(malicious: int, total: int = 70, label: str | None = "trojan.fake") -> dict[str, Any]:
    results = {f"AV{i}": {"category": "malicious" if i < malicious else "undetected",
                          "result": "Fake.Trojan" if i < malicious else None} for i in range(total)}
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "undetected": total - malicious, "harmless": 0},
        "last_analysis_results": results, "last_analysis_date": 1_790_000_000,
        "popular_threat_classification": {"suggested_threat_label": label} if label else {},
        "sandbox_verdicts": {"SandboxA": {"category": "malicious"}} if malicious else {}}}}


class FakeVT:
    """Stands in for urllib.request.urlopen. Records every request."""

    def __init__(self, answers: dict[str, Any] | None = None, status: int | None = None) -> None:
        self.answers = answers or {}
        self.status = status
        self.requests: list[Any] = []

    def __call__(self, req, timeout=None):  # type: ignore[no-untyped-def]
        self.requests.append(req)
        if self.status:
            raise urllib.error.HTTPError(req.full_url, self.status, "x", {}, io.BytesIO(b""))  # type: ignore[arg-type]
        sha = req.full_url.rsplit("/", 1)[1]
        if sha not in self.answers:
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, io.BytesIO(b""))  # type: ignore[arg-type]

        class Resp(io.BytesIO):
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *a):  # type: ignore[no-untyped-def]
                return False

        return Resp(json.dumps(self.answers[sha]).encode())


def engine(db: Database, fake: FakeVT, tmp_path: Path, *, per_minute: int = 4, key: str | None = KEY,
           max_wait: float = 0.0) -> VirusTotalEngine:
    client = VtClient(lambda: key, quota_file=tmp_path / "quota.json", opener=fake, per_minute=per_minute)
    return VirusTotalEngine(db, client, lambda: key is not None, max_wait_s=max_wait)


def exe(tmp_path: Path, name: str, data: bytes) -> ScanTarget:
    p = tmp_path / name
    p.write_bytes(b"MZ" + data)
    return ScanTarget(p, sha256_file(p), p.stat().st_size)


def test_parse_report() -> None:
    r = parse_report("x", payload(12))
    assert (r["found"], r["malicious"], r["engines_total"], r["threat_label"], r["sandbox_malicious"]) == (
        1, 12, 70, "trojan.fake", 1)
    assert len(r["names"]) == 12 and r["last_analysis"].startswith("2026")
    assert parse_report("x", None)["found"] == 0


def test_grading_by_number_of_engines() -> None:
    from sentinelx.core.enums import Severity
    from sentinelx.core.models import DetectionRecord

    def rec(n: int, total: int = 70) -> DetectionRecord:
        return DetectionRecord("VirusTotal", "1.0", "VirusTotal.consensus", Severity.HIGH,
                               {"malicious": n, "engines_total": total}, "s", "t")

    # Audit 8 (H2): alone, strong only with at least 25 engines AND more than half of them.
    assert grade(rec(40))[0] is Reliability.STRONG
    assert grade(rec(25, total=40))[0] is Reliability.STRONG
    assert grade(rec(30))[0] is Reliability.MODERATE  # 30 of 70: not a majority (grey software)
    assert grade(rec(20, total=30))[0] is Reliability.MODERATE  # majority, but under 25 engines
    assert grade(rec(15))[0] is Reliability.MODERATE
    assert grade(rec(5))[0] is Reliability.WEAK
    assert grade(rec(1))[0] is Reliability.WEAK and "誤判" in grade(rec(1))[1]


def test_lookup_sends_only_the_hash(db: Database, tmp_path: Path) -> None:
    t = exe(tmp_path, "a.exe", b"one")
    fake = FakeVT({t.sha256: payload(15)})
    res = engine(db, fake, tmp_path).scan_batch([t], CancelToken())[t]
    assert res.kind is EngineOutcomeKind.FINDINGS and res.detections[0].evidence["malicious"] == 15
    req = fake.requests[0]
    assert req.full_url == f"https://www.virustotal.com/api/v3/files/{t.sha256}"
    assert req.get_method() == "GET" and req.data is None  # nothing uploaded
    assert req.get_header("X-apikey") == KEY


def test_many_engines_make_a_confirmed_threat_and_few_do_not(db: Database, tmp_path: Path) -> None:
    from sentinelx.core.models import FileResult

    bad, grey, meh = exe(tmp_path, "bad.exe", b"bad"), exe(tmp_path, "grey.exe", b"grey"), exe(tmp_path, "meh.exe", b"meh")
    fake = FakeVT({bad.sha256: payload(45), grey.sha256: payload(20), meh.sha256: payload(1)})
    out = engine(db, fake, tmp_path, per_minute=10).scan_batch([bad, grey, meh], CancelToken())
    clean_av = FakeEngine().scan_batch([bad, grey, meh], CancelToken())
    a = {t.path.name: assess(FileResult(t.path, 1, None, None, t.sha256, (out[t], clean_av[t]))) for t in (bad, grey, meh)}
    assert a["bad.exe"].classification is Classification.CONFIRMED_THREAT  # 45 of 70
    assert a["grey.exe"].classification is Classification.SUSPICIOUS  # 20 of 70: reported, not confirmed
    assert a["meh.exe"].classification is Classification.CLEAN  # one engine of 70 is not enough


def test_not_found_is_not_counted_as_a_clean_check(db: Database, tmp_path: Path) -> None:
    from sentinelx.core.models import FileResult

    t = exe(tmp_path, "new.exe", b"never seen")
    res = engine(db, FakeVT(), tmp_path).scan_batch([t], CancelToken())[t]
    assert res.kind is EngineOutcomeKind.NO_FINDINGS and res.info["found"] is False
    a = assess(FileResult(t.path, 1, None, None, t.sha256, (res,)))
    assert a.classification is Classification.UNKNOWN  # VirusTotal alone, file unknown there: no conclusion


def test_cache_avoids_a_second_request(db: Database, tmp_path: Path) -> None:
    t = exe(tmp_path, "a.exe", b"x")
    fake = FakeVT({t.sha256: payload(0)})
    e = engine(db, fake, tmp_path)
    e.scan_batch([t], CancelToken())
    e.scan_batch([t], CancelToken())
    assert len(fake.requests) == 1 and e.report(t.sha256)["from_cache"]


def test_rate_limit_skips_without_making_files_unassessed(db: Database, tmp_path: Path) -> None:
    targets = [exe(tmp_path, f"f{i}.exe", bytes([i])) for i in range(6)]
    fake = FakeVT({t.sha256: payload(0) for t in targets})
    out = engine(db, fake, tmp_path, per_minute=4).scan_batch(targets, CancelToken())
    kinds = [out[t].kind for t in targets]
    assert kinds[:4] == [EngineOutcomeKind.NO_FINDINGS] * 4
    assert kinds[4:] == [EngineOutcomeKind.SKIPPED] * 2 and "上限" in out[targets[4]].info["skip_reason"]
    assert all(r.completed for r in out.values()) and len(fake.requests) == 4


def test_wrong_key_stops_lookups_for_the_batch(db: Database, tmp_path: Path) -> None:
    targets = [exe(tmp_path, f"f{i}.exe", bytes([i])) for i in range(3)]
    fake = FakeVT(status=401)
    out = engine(db, fake, tmp_path, per_minute=10).scan_batch(targets, CancelToken())
    assert len(fake.requests) == 1
    assert all(r.kind is EngineOutcomeKind.SKIPPED for r in out.values())
    assert "金鑰" in out[targets[0]].info["skip_reason"]


def test_daily_quota(db: Database, tmp_path: Path) -> None:
    t = exe(tmp_path, "a.exe", b"q")
    fake = FakeVT({t.sha256: payload(0)})
    client = VtClient(lambda: KEY, quota_file=tmp_path / "quota.json", opener=fake, per_day=1, per_minute=10)
    e = VirusTotalEngine(db, client, lambda: True, max_wait_s=0)
    e.scan_batch([t], CancelToken())
    t2 = exe(tmp_path, "b.exe", b"q2")
    r = e.scan_batch([t2], CancelToken())[t2]
    assert r.kind is EngineOutcomeKind.SKIPPED and "用完" in r.info["skip_reason"] and len(fake.requests) == 1


def test_other_file_types_are_not_looked_up(db: Database, tmp_path: Path) -> None:
    p = tmp_path / "notes.txt"
    p.write_text("hello")
    t = ScanTarget(p, sha256_file(p), p.stat().st_size)
    fake = FakeVT()
    assert engine(db, fake, tmp_path).scan_batch([t], CancelToken())[t].kind is EngineOutcomeKind.SKIPPED
    assert fake.requests == []


def test_scan_end_to_end_with_orchestrator(db: Database, tmp_path: Path) -> None:
    t = exe(tmp_path, "setup.exe", b"bad installer")
    vt = engine(db, FakeVT({t.sha256: payload(45)}), tmp_path)
    orch = ScanOrchestrator([FakeEngine(), vt], ScanRepository(db), ScanLimits())
    s = orch.run([t.path], ExclusionSet(), CancelToken())
    rows = ScanRepository(db).job_files(s.job_id)
    assert rows[0].classification is Classification.CONFIRMED_THREAT
    assert any("VirusTotal" in d for d in rows[0].detections)


# ---------------- key handling ----------------
def test_key_is_encrypted_and_never_logged(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    vt = c.virustotal
    with pytest.raises(ValueError):
        vt.save_key("too-short")
    vt.set_consent(True)
    vt.save_key(KEY)
    raw = (c.paths.root / "virustotal.key").read_bytes()
    assert KEY.encode() not in raw and SecretFile(c.paths.root / "virustotal.key").load() == KEY
    assert vt.enabled() and vt.key() == KEY
    with c.db.engine.connect() as conn:
        audit = " ".join(r[0] for r in conn.execute(text("SELECT detail_json FROM audit_log")))
    assert KEY not in audit
    assert KEY not in (c.paths.config_file).read_text(encoding="utf-8")
    for log in c.paths.log_dir.glob("*"):
        assert KEY not in log.read_text(encoding="utf-8", errors="ignore")
    vt.set_consent(False)
    assert not vt.enabled() and vt.key() is None  # no consent: the key is not used
    vt.delete_key()
    assert not (c.paths.root / "virustotal.key").exists()


def test_engine_unavailable_without_consent_and_key(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    assert not c.virustotal.engine.availability().available  # type: ignore[union-attr]
    c.virustotal.set_consent(True)
    assert not c.virustotal.engine.availability().available  # type: ignore[union-attr]  # still no key
    c.virustotal.save_key(KEY)
    assert c.virustotal.engine.availability().available  # type: ignore[union-attr]


def test_connection_test_uses_the_harmless_eicar_hash(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    vt = c.virustotal
    fake = FakeVT({EICAR_SHA256: payload(60)})
    client = VtClient(vt.key, quota_file=tmp_path / "q.json", opener=fake)
    vt.attach(client, VirusTotalEngine(c.db, client, vt.enabled))
    with pytest.raises(ValueError):
        vt.test_connection()  # not set up yet
    vt.set_consent(True)
    vt.save_key(KEY)
    assert "60" in vt.test_connection() and fake.requests[0].full_url.endswith(EICAR_SHA256)


def test_settings_page_flow(qtbot, make_container: MakeContainer) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.gui.settings_page import SettingsPage

    c = make_container([FakeEngine()])
    p = SettingsPage(c.settings, confirm=lambda *a: True, opener=lambda _p: True, restarter=lambda: True,
                     virustotal=c.virustotal)
    qtbot.addWidget(p)
    assert "尚未同意" in p.vt_status.text() and not p.vt_save_button.isEnabled()
    p.vt_consent.setChecked(True)
    assert p.vt_save_button.isEnabled() and "還沒有儲存" in p.vt_status.text()
    p.vt_key.setText("not a key")
    p._vt_save()
    assert p.vt_key.text() == "" and not c.virustotal.enabled()
    p.vt_key.setText(KEY)
    p._vt_save()
    assert p.vt_key.text() == "" and c.virustotal.enabled() and "已啟用" in p.vt_status.text()
    assert p.vt_test_button.isEnabled()
    p._vt_delete()
    assert not c.virustotal.enabled()


def test_real_app_has_the_engine_and_home_row(tmp_path: Path) -> None:
    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.app.paths import AppPaths
    from sentinelx.core.enums import PrivilegeLevel

    c = bootstrap(AppPaths(tmp_path / "SX"), console_log=False, privilege=PrivilegeLevel.STANDARD)
    try:
        assert "VirusTotal" in [e.name for e in c.engines]
        assert not c.virustotal.enabled()
    finally:
        c.shutdown()


def test_daily_quota_resets_at_utc_midnight_like_virustotal(db: Database, tmp_path: Path) -> None:
    """Taiwan 07:59 is still the previous UTC day; 08:00 is a new one."""
    from datetime import UTC, datetime, timedelta, timezone

    tw = timezone(timedelta(hours=8))
    now = {"t": datetime(2026, 11, 6, 7, 0, tzinfo=tw)}
    t1, t2, t3 = (exe(tmp_path, f"d{i}.exe", bytes([i])) for i in range(3))
    fake = FakeVT({t.sha256: payload(0) for t in (t1, t2, t3)})
    client = VtClient(lambda: KEY, quota_file=tmp_path / "quota.json", opener=fake, per_day=1, per_minute=10,
                      utc_now=lambda: now["t"].astimezone(UTC))
    e = VirusTotalEngine(db, client, lambda: True, max_wait_s=0)
    assert e.scan_batch([t1], CancelToken())[t1].kind is EngineOutcomeKind.NO_FINDINGS
    now["t"] = datetime(2026, 11, 6, 7, 59, tzinfo=tw)  # same UTC day: still used up
    assert e.scan_batch([t2], CancelToken())[t2].kind is EngineOutcomeKind.SKIPPED
    now["t"] = datetime(2026, 11, 6, 8, 0, tzinfo=tw)  # 00:00 UTC: reset
    assert e.scan_batch([t3], CancelToken())[t3].kind is EngineOutcomeKind.NO_FINDINGS
    assert client.used_today() == 1
