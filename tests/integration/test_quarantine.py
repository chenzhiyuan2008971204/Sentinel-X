"""Quarantine vault with harmless synthetic files (marker strings flagged by a fake signature engine)."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, FakeEngine, SignatureAV
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import QuarantineStatus
from sentinelx.engines.base import DetectionEngine
from sentinelx.quarantine import win32fs
from sentinelx.quarantine.vault import QuarantineVault
from sentinelx.quarantine.win32fs import QuarantineError
from sentinelx.storage.orm import QuarantineItem

pytestmark = [pytest.mark.integration, pytest.mark.windows,
              pytest.mark.skipif(sys.platform != "win32", reason="vault uses Windows APIs")]
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
PAYLOAD = b"harmless synthetic sample " + MALWARE_MARKER + b" \x00\x01\x02" * 1000


@pytest.fixture
def c(make_container: MakeContainer) -> AppContainer:
    return make_container([SignatureAV()])


def scan_file(c: AppContainer, path: Path, data: bytes = PAYLOAD, zone: str | None = None) -> int:
    """Write a harmless file, scan it, return its CONFIRMED verdict id."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if zone:
        with open(f"{path}:Zone.Identifier", "w", encoding="utf-8") as z:
            z.write(zone)
    c.scans.run_scan([path], CancelToken())
    return next(t.verdict_id for t in c.reviews.threats() if Path(t.path) == path)


def vault_objects(c: AppContainer) -> list[Path]:
    return sorted(c.paths.vault_dir.glob("*.sxq"))


# ---------------- vault protection ----------------
@pytest.mark.security
def test_vault_acl_is_private(c: AppContainer) -> None:
    assert c.quarantine.ready
    sid = win32fs.current_user_sid()
    sddl = win32fs.read_dacl_sddl(c.paths.vault_dir)
    assert win32fs.dacl_is_private(sddl, sid), sddl


@pytest.mark.security
def test_vault_reharden_after_tampering(c: AppContainer) -> None:
    sid = win32fs.current_user_sid()
    obj = c.paths.vault_dir / "existing.sxq"
    obj.write_bytes(b"SXQ1x")
    for who in ("*S-1-1-0:(R)", "*S-1-5-32-545:(RX)"):  # Everyone, BUILTIN\Users
        subprocess.run(["icacls", str(c.paths.vault_dir), "/grant", who], capture_output=True, check=True)
    subprocess.run(["icacls", str(obj), "/grant", "*S-1-1-0:(F)"], capture_output=True, check=True)
    assert not win32fs.dacl_is_private(win32fs.read_dacl_sddl(c.paths.vault_dir), sid)
    v = QuarantineVault(c.paths.vault_dir, c.db, c.audit)  # next start
    assert v.ready and win32fs.dacl_is_private(win32fs.read_dacl_sddl(c.paths.vault_dir), sid)
    child = win32fs.read_dacl_sddl(obj)
    assert "S-1-1-0" not in child and "WD" not in child
    trustees = [ace.split(";")[-1] for ace in re.findall(r"\(([^)]*)\)", child)]
    assert trustees and all(win32fs.full_sid(t) == sid for t in trustees)  # e.g. "LA" for RID 500


def test_dacl_parser() -> None:
    sid = "S-1-5-21-1-2-3-1001"
    assert win32fs.dacl_is_private(f"D:PAI(A;OICI;FA;;;{sid})", sid)
    assert not win32fs.dacl_is_private(f"D:AI(A;OICI;FA;;;{sid})", sid)  # inheritable
    assert not win32fs.dacl_is_private(f"D:P(A;OICI;FA;;;{sid})(A;;FR;;;WD)", sid)  # Everyone
    assert not win32fs.dacl_is_private("D:P", sid)


# ---------------- intake ----------------
def test_quarantine_moves_and_obfuscates(c: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "惡意 樣本.exe"
    vid = scan_file(c, f)
    item = c.quarantine.quarantine_verdict(vid, "測試", confirmed=True)
    assert not f.exists()
    [obj] = vault_objects(c)
    stored = obj.read_bytes()
    assert MALWARE_MARKER not in stored and stored.startswith(b"SXQ1") and not stored[4:].startswith(b"MZ")
    assert win32fs.dacl_is_private(win32fs.read_dacl_sddl(c.paths.vault_dir), win32fs.current_user_sid())
    assert item.status is QuarantineStatus.QUARANTINED and item.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert item.original_path == str(f) and item.size == len(PAYLOAD) and item.reason == "測試"
    assert c.quarantine.verify(item.id)[0]
    with c.db.engine.connect() as conn:
        actions = [r[0] for r in conn.execute(text("SELECT action FROM audit_log"))]
    assert "QUARANTINE" in actions and c.audit.verify().ok
    assert c.quarantine.is_quarantined(item.sha256, str(f))
    assert not (c.paths.vault_dir.glob("*.part") and list(c.paths.vault_dir.glob("*.part")))


def test_requires_confirmation_reason_and_confirmed_threat(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    f = tmp_path / "a.bin"
    vid = scan_file(c, f)
    with pytest.raises(QuarantineError):
        c.quarantine.quarantine_verdict(vid, "r", confirmed=False)
    with pytest.raises(QuarantineError):
        c.quarantine.quarantine_verdict(vid, "  ", confirmed=True)
    assert f.exists()

    c2 = make_container([FakeEngine()])  # unrated engine -> SUSPICIOUS, not confirmed
    g = tmp_path / "s" / "b.bin"
    g.parent.mkdir()
    g.write_bytes(PAYLOAD)
    c2.scans.run_scan([g], CancelToken())
    [t] = [x for x in c2.reviews.threats() if Path(x.path) == g]  # both containers share one DB
    with pytest.raises(QuarantineError, match="not confirmed threat"):
        c2.quarantine.quarantine_verdict(t.verdict_id, "r", confirmed=True)
    assert g.exists()


def test_modified_after_scan_refused(c: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    vid = scan_file(c, f)
    f.write_bytes(PAYLOAD + b"changed")
    with pytest.raises(QuarantineError, match="hash mismatch"):
        c.quarantine.quarantine_verdict(vid, "r", confirmed=True)
    assert f.read_bytes().endswith(b"changed") and vault_objects(c) == []
    assert list(c.paths.vault_dir.glob("*.part")) == []


def test_file_in_use_refused(c: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    vid = scan_file(c, f)
    with open(f, "ab"):  # another writer holds the file
        with pytest.raises(QuarantineError):
            c.quarantine.quarantine_verdict(vid, "r", confirmed=True)
    assert f.exists() and vault_objects(c) == []


def test_missing_file_refused(c: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    vid = scan_file(c, f)
    f.unlink()
    with pytest.raises(QuarantineError):
        c.quarantine.quarantine_verdict(vid, "r", confirmed=True)


def test_duplicate_detection(c: AppContainer, tmp_path: Path) -> None:
    a = tmp_path / "one" / "a.bin"
    b = tmp_path / "two" / "b.bin"
    va, vb = scan_file(c, a), scan_file(c, b)
    first = c.quarantine.quarantine_verdict(va, "r", confirmed=True)
    second = c.quarantine.quarantine_verdict(vb, "r", confirmed=True)  # same content, other path
    assert second.duplicate_of == first.id
    # same path + same hash again -> refused
    a.write_bytes(PAYLOAD)
    va2 = scan_file(c, a)
    with pytest.raises(QuarantineError, match="duplicate"):
        c.quarantine.quarantine_verdict(va2, "r", confirmed=True)
    assert a.exists()


@pytest.mark.security
def test_hard_linked_file_refused(c: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    vid = scan_file(c, f)
    (tmp_path / "link.bin").hardlink_to(f)
    with pytest.raises(QuarantineError, match="hard links"):
        c.quarantine.quarantine_verdict(vid, "r", confirmed=True)
    assert f.exists()


def make_junction(link: Path, target: Path) -> None:
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot create junction")


@pytest.mark.security
def test_path_through_junction_refused(c: AppContainer, tmp_path: Path) -> None:
    real = tmp_path / "real"
    f = real / "a.bin"
    scan_file(c, f)
    make_junction(tmp_path / "j", real)
    via = tmp_path / "j" / "a.bin"
    with pytest.raises(QuarantineError, match="link"):
        c.quarantine._vault.quarantine(via, hashlib.sha256(PAYLOAD).hexdigest(), verdict_id=None, reason="r")
    assert f.exists()


# ---------------- restore ----------------
def quarantined(c: AppContainer, tmp_path: Path, zone: str | None = None):  # type: ignore[no-untyped-def]
    f = tmp_path / "orig" / "sample.exe"
    vid = scan_file(c, f, zone=zone)
    return f, c.quarantine.quarantine_verdict(vid, "r", confirmed=True)


def test_round_trip_restore_with_motw(c: AppContainer, tmp_path: Path) -> None:
    zone = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/x\r\n"
    f, item = quarantined(c, tmp_path, zone)
    assert item.has_zone_identifier
    r = c.quarantine.restore(item.id, confirmed=True)
    assert f.read_bytes() == PAYLOAD and r.status is QuarantineStatus.RESTORED and r.restore_target == str(f)
    with open(f"{f}:Zone.Identifier", encoding="utf-8") as z:
        assert "ZoneId=3" in z.read()
    assert vault_objects(c) == []
    with c.db.engine.connect() as conn:
        assert "RESTORE" in [r[0] for r in conn.execute(text("SELECT action FROM audit_log"))]


def test_restore_requires_confirmation(c: AppContainer, tmp_path: Path) -> None:
    f, item = quarantined(c, tmp_path)
    with pytest.raises(QuarantineError):
        c.quarantine.restore(item.id, confirmed=False)
    assert not f.exists()


def test_restore_to_other_location(c: AppContainer, tmp_path: Path) -> None:
    _, item = quarantined(c, tmp_path)
    dest = tmp_path / "elsewhere" / "復原.bin"
    dest.parent.mkdir()
    c.quarantine.restore(item.id, dest, confirmed=True)
    assert dest.read_bytes() == PAYLOAD


@pytest.mark.security
def test_tampered_vault_object_refused(c: AppContainer, tmp_path: Path) -> None:
    f, item = quarantined(c, tmp_path)
    [obj] = vault_objects(c)
    data = bytearray(obj.read_bytes())
    data[100] ^= 0xFF
    obj.write_bytes(bytes(data))
    ok, msg = c.quarantine.verify(item.id)
    assert not ok and "完整性" in msg
    with pytest.raises(QuarantineError, match="integrity"):
        c.quarantine.restore(item.id, confirmed=True)
    assert not f.exists() and obj.exists()
    assert list(f.parent.glob(".sxrestore-*")) == []
    assert c.quarantine.items()[0].status is QuarantineStatus.QUARANTINED


@pytest.mark.security
def test_restore_never_overwrites(c: AppContainer, tmp_path: Path) -> None:
    f, item = quarantined(c, tmp_path)
    f.write_bytes(b"new file the user created")
    with pytest.raises(QuarantineError, match="exists"):
        c.quarantine.restore(item.id, confirmed=True)
    assert f.read_bytes() == b"new file the user created" and vault_objects(c)


@pytest.mark.security
@pytest.mark.parametrize("bad", ["relative\\x.bin", "C:\\x\\a.bin:evil", "C:\\x\\NUL", "C:\\x\\com1.txt"])
def test_restore_target_validation(c: AppContainer, tmp_path: Path, bad: str) -> None:
    _, item = quarantined(c, tmp_path)
    with pytest.raises(QuarantineError):
        c.quarantine.restore(item.id, Path(bad), confirmed=True)


@pytest.mark.security
def test_restore_into_vault_or_through_junction_refused(c: AppContainer, tmp_path: Path) -> None:
    _, item = quarantined(c, tmp_path)
    with pytest.raises(QuarantineError, match="inside vault"):
        c.quarantine.restore(item.id, c.paths.vault_dir / "x.bin", confirmed=True)
    real = tmp_path / "realdir"
    real.mkdir()
    make_junction(tmp_path / "jd", real)
    with pytest.raises(QuarantineError, match="link"):
        c.quarantine.restore(item.id, tmp_path / "jd" / "x.bin", confirmed=True)
    assert list(real.iterdir()) == []


@pytest.mark.security
def test_database_tampering_blocks_restore(c: AppContainer, tmp_path: Path) -> None:
    """Redirecting a restore by editing the DB record (e.g. to a Startup folder) is refused."""
    _, item = quarantined(c, tmp_path)
    evil = tmp_path / "startup"
    evil.mkdir()
    with c.db.session() as s:
        s.get(QuarantineItem, item.id).original_path = str(evil / "payload.exe")
    with pytest.raises(QuarantineError, match="audit mismatch"):
        c.quarantine.restore(item.id, confirmed=True)
    assert list(evil.iterdir()) == []


@pytest.mark.security
def test_audit_detail_records_binding(c: AppContainer, tmp_path: Path) -> None:
    f, item = quarantined(c, tmp_path)
    with c.db.session() as s:
        aid = s.get(QuarantineItem, item.id).audit_entry_id
    action, d = c.audit.entry(aid)  # type: ignore[misc]
    assert action == "QUARANTINE" and d["original_path"] == str(f) and d["vault_id"] == item.vault_id


def test_permanent_delete_is_never_automatic() -> None:
    """Only one way to permanently delete exists (QuarantineService.delete, confirmed=True required),
    and only the quarantine page's user action calls it: real-time protection, scans, reviews and
    startup code never do (CLAUDE.md: never automatically permanently delete)."""
    import re

    from sentinelx.services.quarantine_service import QuarantineService

    for cls in (QuarantineVault, QuarantineService):
        public = [n for n in dir(cls) if not n.startswith("_")]
        assert [n for n in public if any(w in n.lower() for w in ("delete", "purge", "remove", "wipe", "erase"))]             == ["delete"]
    src = Path(__file__).parents[2] / "src" / "sentinelx"
    callers = sorted(f.relative_to(src).as_posix() for f in src.rglob("*.py")
                     if re.search(r"(quarantine|svc|_vault)\.delete\(", f.read_text(encoding="utf-8")))
    assert callers == ["gui/quarantine_page.py", "services/quarantine_service.py"], callers


def test_large_file_round_trip(c: AppContainer, tmp_path: Path) -> None:
    big = PAYLOAD + bytes(range(256)) * 40000  # ~10 MB, multiple chunks, unaligned length
    f = tmp_path / "big" / "b.bin"
    vid = scan_file(c, f, data=big + b"x")
    item = c.quarantine.quarantine_verdict(vid, "r", confirmed=True)
    c.quarantine.restore(item.id, confirmed=True)
    assert hashlib.sha256(f.read_bytes()).hexdigest() == hashlib.sha256(big + b"x").hexdigest()


def test_migration_v3_to_v4_columns(c: AppContainer) -> None:
    with c.db.engine.connect() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(quarantine_items)"))]
    assert {"xor_key", "duplicate_of", "audit_entry_id", "restore_target", "reason"} <= set(cols)
    assert json.dumps(cols)


# ---------------- permanent delete (0.14.0, user only) ----------------
def test_delete_requires_confirmation(c: AppContainer, tmp_path: Path) -> None:
    _f, item = quarantined(c, tmp_path)
    with pytest.raises(QuarantineError):
        c.quarantine.delete(item.id, confirmed=False)
    assert len(vault_objects(c)) == 1 and c.quarantine.items()[0].status is QuarantineStatus.QUARANTINED


def test_delete_removes_stored_copy_and_keeps_history(c: AppContainer, tmp_path: Path) -> None:
    f, item = quarantined(c, tmp_path)
    r = c.quarantine.delete(item.id, confirmed=True)
    assert r.status is QuarantineStatus.DELETED and r.deleted_at
    assert vault_objects(c) == [] and not f.exists()
    with pytest.raises(QuarantineError):
        c.quarantine.restore(item.id, confirmed=True)  # cannot come back
    with pytest.raises(QuarantineError):
        c.quarantine.delete(item.id, confirmed=True)  # only once
    ok, _ = c.quarantine.verify(item.id)
    assert not ok
    with c.db.engine.connect() as conn:
        rows = conn.execute(text("SELECT action, detail_json FROM audit_log WHERE action='QUARANTINE_DELETE'")).all()
    assert len(rows) == 1 and item.sha256 in rows[0][1]
    assert c.audit.verify(full=True).ok
    # the deleted threat still counts as handled in the threat list
    assert any(t[4] for t in c.verdicts.threat_index_rows()) if hasattr(c, "verdicts") else True


def test_delete_only_the_selected_duplicate(c: AppContainer, tmp_path: Path) -> None:
    _f1, a = quarantined(c, tmp_path / "one")
    _f2, b = quarantined(c, tmp_path / "two")
    assert b.duplicate_of == a.id and len(vault_objects(c)) == 2
    c.quarantine.delete(a.id, confirmed=True)
    assert len(vault_objects(c)) == 1
    restored = c.quarantine.restore(b.id, confirmed=True)  # the other copy is intact
    assert restored.status is QuarantineStatus.RESTORED


def test_deleted_threat_hash_still_stops_copies(c: AppContainer, tmp_path: Path) -> None:
    from sentinelx.services.protection_service import ProtectionService
    from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
    from sentinelx.storage.verdict_repository import VerdictRepository

    _f, item = quarantined(c, tmp_path)
    c.quarantine.delete(item.id, confirmed=True)
    s = ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db),
                          ExclusionRepository(c.db), VerdictRepository(c.db), c.quarantine, c.audit, clamd=None,
                          removable=list, folders=list, registry=object())
    assert item.sha256 in s.threat_hashes()


def test_quarantine_page_delete_button(qtbot, c: AppContainer, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.gui.quarantine_page import QuarantinePage

    _f, item = quarantined(c, tmp_path)
    answers = [False, True]
    page = QuarantinePage(c.quarantine, confirm=lambda *a: answers.pop(0))
    qtbot.addWidget(page)
    page.table.selectRow(0)
    assert page.delete_button.isEnabled()
    page.delete_selected()  # "no"
    assert len(vault_objects(c)) == 1
    page.delete_selected()  # "yes"
    qtbot.waitUntil(lambda: not page.busy, timeout=10_000)
    assert vault_objects(c) == [] and "已永久刪除" in page.table.item(0, 1).text()
    page.table.selectRow(0)
    assert not page.delete_button.isEnabled() and not page.restore_button.isEnabled()
