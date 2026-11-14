"""Verdict persistence during scans, re-assessment, and the manual review workflow."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import ENGINE_ERROR_MARKER, MALWARE_MARKER, FakeEngine, SignatureAV
from sqlalchemy import select, text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import Classification as C
from sentinelx.core.enums import ExclusionKind, ReviewDecision
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.pe_static import PEStaticEngine
from sentinelx.storage.orm import FileScan, FpSuppression, Verdict

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "t"
    root.mkdir()
    (root / "bad.bin").write_bytes(MALWARE_MARKER)
    (root / "clean.txt").write_text("hello")
    (root / "err.txt").write_bytes(ENGINE_ERROR_MARKER)
    (root / "skip.log").write_text("excluded")
    return root


def scan(c: AppContainer, root: Path):  # type: ignore[no-untyped-def]
    return c.scans.run_scan([root], CancelToken())


def files(c: AppContainer, job_id: int) -> dict[str, object]:
    return {Path(f.path).name: f for f in c.scans.job_files(job_id)}


def test_scan_assigns_verdicts(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV(), FakeEngine()])
    c.scans.add_exclusion(ExclusionKind.EXTENSION, ".log")
    s = scan(c, tree)
    assert (s.confirmed, s.suspicious, s.unknown, s.clean) == (1, 0, 1, 1)
    f = files(c, s.job_id)
    assert f["bad.bin"].classification is C.CONFIRMED_THREAT  # type: ignore[attr-defined]
    assert f["clean.txt"].classification is C.CLEAN  # type: ignore[attr-defined]
    assert f["err.txt"].classification is C.UNKNOWN  # FakeAV failed on it  # type: ignore[attr-defined]
    assert f["skip.log"].classification is None  # excluded: no verdict  # type: ignore[attr-defined]
    job = c.scans.history()[0]
    assert (job.confirmed, job.suspicious, job.unknown) == (1, 0, 1)


def test_verdict_links_contributing_detections(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV(), FakeEngine()])
    s = scan(c, tree)
    vid = files(c, s.job_id)["bad.bin"].verdict_id  # type: ignore[attr-defined]
    with c.db.session() as sess:
        v = sess.get(Verdict, vid)
        ids = json.loads(v.contributing_detection_ids)
        rules = {r for (r,) in sess.execute(text(f"SELECT rule_id FROM detections WHERE id IN ({','.join(map(str, ids))})"))}
        assert rules == {"Sentinel.Test.Marker-1", "Test.Marker"}
        assert v.confidence == "高" and v.assessor_version == "risk-rules-4"
        assert "分類：確認威脅" in v.explanation and "不是惡意程式的機率" in v.explanation


def test_rescan_supersedes_previous_verdict(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV()])
    scan(c, tree)
    scan(c, tree)
    with c.db.session() as s:
        latest = s.scalars(select(Verdict).where(Verdict.superseded_by.is_(None))).all()
        everything = s.scalars(select(Verdict)).all()
    assert len(everything) == 2 * len(latest)
    assert c.reviews.class_counts()[C.CONFIRMED_THREAT] == 1


def test_unreadable_or_limited_file_gets_unknown(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    c.config.scan.max_file_size_mb = 1
    big = tmp_path / "big.bin"
    with open(big, "wb") as f:
        f.truncate(2 * 1024 * 1024)
    s = c.scans.run_scan([tmp_path], CancelToken())
    assert s.unknown == 1 and s.status == "PARTIAL"


# ---------------- review workflow ----------------
def latest_threat(c: AppContainer):  # type: ignore[no-untyped-def]
    [t] = c.reviews.threats()
    return t


def test_threat_list_and_detail(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV(), FakeEngine()])
    scan(c, tree)
    t = latest_threat(c)
    assert t.classification is C.CONFIRMED_THREAT and Path(t.path).name == "bad.bin"
    assert "Sentinel.Test.Marker-1" in t.summary
    d = c.reviews.detail(t.verdict_id)
    assert d is not None and {r.engine_name for r in d.results} == {"ClamAV", "FakeAV"}
    assert len(d.history) == 1
    assert len(c.reviews.threats(include_resolved=True)) == 4  # every file's latest verdict (no exclusions here)


def test_reason_is_required(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV()])
    scan(c, tree)
    with pytest.raises(ValueError):
        c.reviews.review(latest_threat(c).verdict_id, ReviewDecision.CONFIRM, "   ")


def test_dismiss_false_positive_by_rules(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV()])
    scan(c, tree)
    old = latest_threat(c)
    new_id = c.reviews.review(old.verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "內部測試工具")
    assert new_id != old.verdict_id
    new = c.reviews.detail(new_id)
    assert new is not None and new.row.classification is C.CLEAN
    assert "已標記誤判：內部測試工具" in new.explanation
    assert c.reviews.threats() == []
    [sup] = c.reviews.suppressions()
    assert sup.rule_id == "Sentinel.Test.Marker-1" and sup.sha256 == old.sha256
    # Old verdict and its evidence are kept; review is attached to the old verdict.
    old_detail = c.reviews.detail(old.verdict_id)
    assert old_detail is not None and old_detail.reviews[0][1] is ReviewDecision.DISMISS_FALSE_POSITIVE
    with pytest.raises(ValueError):  # cannot review a superseded verdict
        c.reviews.review(old.verdict_id, ReviewDecision.CONFIRM, "again")


def test_suppression_applies_to_future_scans(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV()])
    scan(c, tree)
    c.reviews.review(latest_threat(c).verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "fp")
    s = scan(c, tree)
    assert s.confirmed == 0 and files(c, s.job_id)["bad.bin"].classification is C.CLEAN  # type: ignore[attr-defined]


def test_whole_file_suppression(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV(), FakeEngine()])
    scan(c, tree)
    c.reviews.review(latest_threat(c).verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "fp", scope="file")
    [sup] = c.reviews.suppressions()
    assert sup.rule_id is None
    assert c.reviews.threats() == []


def test_removing_suppression_restores_verdict(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV()])
    scan(c, tree)
    c.reviews.review(latest_threat(c).verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "fp")
    [sup] = c.reviews.suppressions()
    assert c.reviews.remove_suppression(sup.id)
    assert latest_threat(c).classification is C.CONFIRMED_THREAT
    with c.db.session() as s:
        assert s.get(FpSuppression, sup.id).active == 0  # deactivated, not deleted


def test_confirm_suspicious_by_human(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([FakeEngine()])  # unrated engine -> SUSPICIOUS
    scan(c, tree)
    t = latest_threat(c)
    assert t.classification is C.SUSPICIOUS and t.needs_review
    new_id = c.reviews.review(t.verdict_id, ReviewDecision.CONFIRM, "人工逆向分析確認")
    d = c.reviews.detail(new_id)
    assert d is not None and d.row.classification is C.CONFIRMED_THREAT
    assert d.row.confidence == "人工確認" and not d.row.needs_review
    assert "由使用者人工確認" in d.explanation and "自動評估" in d.explanation


def test_escalate_keeps_verdict_open(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([FakeEngine()])
    scan(c, tree)
    t = latest_threat(c)
    assert c.reviews.review(t.verdict_id, ReviewDecision.ESCALATE, "交給資安團隊") == t.verdict_id
    t2 = latest_threat(c)
    assert t2.last_review is ReviewDecision.ESCALATE and t2.needs_review


def test_reviews_are_audited(make_container: MakeContainer, tree: Path) -> None:
    c = make_container([SignatureAV()])
    scan(c, tree)
    c.reviews.review(latest_threat(c).verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "fp")
    with c.db.engine.connect() as conn:
        actions = [r[0] for r in conn.execute(text("SELECT action FROM audit_log"))]
    assert "REVIEW_DISMISS_FALSE_POSITIVE" in actions and c.audit.verify().ok


def test_file_scan_keeps_scan_time_verdict(make_container: MakeContainer, tree: Path) -> None:
    """History shows what was decided at scan time even after a later review changes it."""
    c = make_container([SignatureAV()])
    s = scan(c, tree)
    c.reviews.review(latest_threat(c).verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "fp")
    assert files(c, s.job_id)["bad.bin"].classification is C.CONFIRMED_THREAT  # type: ignore[attr-defined]
    with c.db.session() as sess:
        assert all(fs.verdict_id for fs in sess.scalars(select(FileScan)) if fs.assessed)


# ---------------- static analysis ----------------
def test_static_analysis_assessment_requires_detection_engine(make_container: MakeContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_text("x")
    rep = make_container([PEStaticEngine()]).static.analyze(f)
    assert rep.assessment is not None and rep.assessment.classification is C.UNKNOWN
    assert "沒有可用的偵測引擎" in rep.assessment.explanation


def test_static_analysis_assessment_with_signature(make_container: MakeContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(MALWARE_MARKER)
    rep = make_container([SignatureAV(), PEStaticEngine()]).static.analyze(f)
    assert rep.assessment is not None and rep.assessment.classification is C.CONFIRMED_THREAT
