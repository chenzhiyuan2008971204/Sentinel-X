"""Regression tests for the Phase 5 engineering audit (ENGINEERING_AUDIT.md, findings B1-B7).

Each test failed before its fix.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import Classification, EngineOutcomeKind, QuarantineStatus
from sentinelx.core.models import DetectionResult, FileResult
from sentinelx.core.risk import assess
from sentinelx.engines.base import DetectionEngine
from sentinelx.quarantine import vault as vault_mod
from sentinelx.quarantine.vault import QuarantineVault
from sentinelx.quarantine.win32fs import QuarantineError

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows APIs")
PAYLOAD = b"audit sample " + MALWARE_MARKER


def confirmed(c: AppContainer, f: Path) -> int:
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(PAYLOAD)
    c.scans.run_scan([f], CancelToken())
    return next(t.verdict_id for t in c.reviews.threats() if Path(t.path) == f)


# ---- B1: a parent swapped for a junction between the path check and the open ----
@windows_only
@pytest.mark.security
def test_B1_handle_final_path_is_verified(make_container: MakeContainer, tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    c = make_container([SignatureAV()])
    real = tmp_path / "real"
    f = real / "a.bin"
    confirmed(c, f)
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "j"), str(real)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot create junction")
    # Simulate losing the race: the pre-open realpath check sees nothing suspicious.
    monkeypatch.setattr(vault_mod.os.path, "realpath", lambda p, *a, **k: str(p))
    with pytest.raises(QuarantineError, match="final path"):
        c.quarantine._vault.quarantine(tmp_path / "j" / "a.bin", hashlib.sha256(PAYLOAD).hexdigest(),
                                       verdict_id=None, reason="r")
    assert f.exists()


# ---- B2: state left by a crash during intake is reconciled at startup ----
@windows_only
def test_B2_interrupted_intake_reconciled(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    f = tmp_path / "a.bin"
    item = c.quarantine.quarantine_verdict(confirmed(c, f), "r", confirmed=True)
    f.write_bytes(PAYLOAD)  # as if the delete never happened (crash after DB write)
    leftover = c.paths.vault_dir / ("0" * 32 + ".part")
    leftover.write_bytes(b"partial")
    QuarantineVault(c.paths.vault_dir, c.db, c.audit)  # next start
    got = c.quarantine._vault.get(item.id)
    assert got is not None and got.status is QuarantineStatus.RETAINED_ERROR
    assert "仍存在" in (got.error_detail or "")
    assert not leftover.exists()


@windows_only
def test_B2_missing_vault_object_flagged(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    item = c.quarantine.quarantine_verdict(confirmed(c, tmp_path / "a.bin"), "r", confirmed=True)
    (c.paths.vault_dir / f"{item.vault_id}.sxq").unlink()
    QuarantineVault(c.paths.vault_dir, c.db, c.audit)
    got = c.quarantine._vault.get(item.id)
    assert got is not None and "遺失" in (got.error_detail or "")


# ---- B3: a restored file is never left with a QUARANTINED record ----
@windows_only
def test_B3_restore_records_before_removing_vault_object(make_container: MakeContainer, tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    c = make_container([SignatureAV()])
    f = tmp_path / "a.bin"
    item = c.quarantine.quarantine_verdict(confirmed(c, f), "r", confirmed=True)
    real_unlink = Path.unlink

    def failing_unlink(self: Path, *a, **k):  # type: ignore[no-untyped-def]
        if self.suffix == ".sxq":
            raise PermissionError(5, "Access is denied")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    got = c.quarantine.restore(item.id, confirmed=True)
    assert f.read_bytes() == PAYLOAD
    assert got.status is QuarantineStatus.RESTORED and "無法移除" in (got.error_detail or "")


# ---- B6: only context engines completed -> never CLEAN ----
@pytest.mark.parametrize("outcomes", [
    (DetectionResult("PEStatic", EngineOutcomeKind.NO_FINDINGS),),
    (DetectionResult("PEStatic", EngineOutcomeKind.SKIPPED),
     DetectionResult("HashIntel", EngineOutcomeKind.NO_FINDINGS, info={"reputation": "UNKNOWN"})),
    (DetectionResult("HashIntel", EngineOutcomeKind.NO_FINDINGS,
                     info={"reputation": "UNKNOWN", "detection_capable": False}),),
])
def test_B6_context_only_results_are_unknown(outcomes: tuple[DetectionResult, ...]) -> None:
    a = assess(FileResult(Path("C:/x"), 1, None, None, "a" * 64, outcomes))
    assert a.classification is Classification.UNKNOWN
    assert "偵測引擎" in a.explanation


def test_B6_hash_intel_with_malicious_entries_still_counts() -> None:
    o = DetectionResult("HashIntel", EngineOutcomeKind.NO_FINDINGS,
                        info={"reputation": "UNKNOWN", "detection_capable": True})
    assert assess(FileResult(Path("C:/x"), 1, None, None, "a" * 64, (o,))).classification is Classification.CLEAN


# ---- B7: threats whose file is gone are labelled ----
def test_B7_missing_file_is_indicated(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    f = tmp_path / "a.bin"
    confirmed(c, f)
    f.unlink()
    [t] = [x for x in c.reviews.threats() if Path(x.path) == f]
    assert t.file_missing
