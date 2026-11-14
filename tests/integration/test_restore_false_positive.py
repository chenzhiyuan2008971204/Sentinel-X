"""Restoring a wrongly blocked file and downloading it again (asked by the user, 2026-11-09).

Before: marking the re-downloaded copy as a false positive left the first copy's "confirmed
threat" verdict and its quarantine entry in place, so the process guard still closed the program
whenever it started. Restoring alone (without marking) blocks the same file again: by design.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from test_protection import service, settle

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import Classification, ReviewDecision
from sentinelx.engines.base import DetectionEngine

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
CONTENT = b"wanted tool " + MALWARE_MARKER


def _blocked_then_restored(c: AppContainer, folder: Path, *, mark_safe: bool):  # type: ignore[no-untyped-def]
    s, _ = service(c, folder)
    s.start()
    first = folder / "tool.exe"
    first.write_bytes(CONTENT)
    settle(s, first)
    assert not first.exists()  # wrongly quarantined
    item = c.quarantine.items()[0]
    c.quarantine.restore(item.id, confirmed=True)
    if mark_safe:
        c.reviews.dismiss_whole_file(item.verdict_id, "my own tool")  # type: ignore[arg-type]
    settle(s, first)  # the restored file is seen again by real-time protection
    return s, first, item


def test_restore_and_mark_safe_lets_the_same_download_through(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    s, first, _item = _blocked_then_restored(c, tmp_path, mark_safe=True)
    try:
        assert first.exists()
        again = tmp_path / "tool (1).exe"  # downloaded again
        again.write_bytes(CONTENT)
        settle(s, again)
        assert again.exists() and len(c.quarantine.items()) == 1  # not quarantined again
        s._hash_cache = (0.0, set())  # the list is re-read every 5 s; read it now
        assert hashlib.sha256(CONTENT).hexdigest() not in s.threat_hashes()  # not closed when it runs
        assert not [t for t in c.reviews.threats() if t.classification is Classification.CONFIRMED_THREAT]
    finally:
        s.stop()


def test_restore_without_marking_blocks_the_same_file_again(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    s, first, _item = _blocked_then_restored(c, tmp_path, mark_safe=False)
    try:
        assert not first.exists() and len(c.quarantine.items()) == 2  # by design: restoring is not trusting
    finally:
        s.stop()


def test_false_positive_on_a_new_copy_clears_older_copies(make_container: MakeContainer, tmp_path: Path) -> None:
    """The user re-downloads first and marks the new copy; the quarantined original must not keep
    the program on the process guard's list."""
    c = make_container([SignatureAV()])
    s, _ = service(c, tmp_path)
    s.start()
    try:
        first = tmp_path / "tool.exe"
        first.write_bytes(CONTENT)
        settle(s, first)
        sha = hashlib.sha256(CONTENT).hexdigest()
        s.update(auto_quarantine=False)
        again = tmp_path / "tool (1).exe"
        again.write_bytes(CONTENT)
        settle(s, again)
        newest = next(t for t in c.reviews.threats() if Path(t.path) == again)
        s._hash_cache = (0.0, set())  # read the list again now
        assert sha in s.threat_hashes()
        c.reviews.review(newest.verdict_id, ReviewDecision.DISMISS_FALSE_POSITIVE, "mine", scope="file")
        s._hash_cache = (0.0, set())
        assert sha not in s.threat_hashes()
        assert not c.reviews.threats()  # the original copy's verdict was re-assessed too
    finally:
        s.stop()


def test_rule_false_positive_keeps_other_evidence(make_container: MakeContainer, tmp_path: Path) -> None:
    """Dismissing one rule re-assesses every copy, but does not clear a verdict that still has
    other strong evidence (here none remains, so it clears; the suppression is per rule)."""
    c = make_container([SignatureAV()])
    s, _ = service(c, tmp_path)
    s.update(auto_quarantine=False)
    s.start()
    try:
        a, b = tmp_path / "a.exe", tmp_path / "b.exe"
        for f in (a, b):
            f.write_bytes(CONTENT)
            settle(s, f)
        vid = next(t.verdict_id for t in c.reviews.threats() if Path(t.path) == a)
        c.reviews.review(vid, ReviewDecision.DISMISS_FALSE_POSITIVE, "rule is wrong")
        assert not [t for t in c.reviews.threats() if t.classification is Classification.CONFIRMED_THREAT]
        assert all(sup.rule_id for sup in c.reviews.suppressions())  # only the rule, not the whole file
    finally:
        s.stop()
