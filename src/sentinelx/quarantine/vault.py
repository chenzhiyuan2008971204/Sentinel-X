"""Quarantine vault.

Intake (quarantine)
  1. The path must not go through a link (realpath == abspath) and must not already be
     quarantined with the same hash (duplicate detection).
  2. The file is opened once, locked against writers, without following reparse points.
  3. Its bytes are streamed through SHA-256 and XOR-obfuscated into `<uuid>.part`, fsynced,
     renamed to `<uuid>.sxq`, then read back and re-hashed. The hash must equal the hash the
     verdict was made on, otherwise nothing is changed ("modified since scan").
  4. The database record and a hash-chained audit entry are written BEFORE the original is
     removed. The original is then deleted through the same handle (the exact file verified).
     If that fails, the vault copy is kept, the item is marked RETAINED_ERROR, and the original
     stays where it was.

Restore
  - Allowed only if the item's audit entry is intact and matches the record (path, hash,
    vault id), so editing the database cannot redirect a restore.
  - Target must be absolute, without ADS syntax or reserved names, not inside the vault, and
    its folder must not be reached through a link. An existing file is never overwritten.
  - The vault object is decoded to a temporary file next to the target, hashed, and only
    renamed into place if the hash matches. Mark-of-the-Web is restored when it was present.

Never deleted automatically: the vault object is removed only after a verified restore.
`.sxq` + XOR means the stored bytes are neither executable nor re-detected by other AV;
this is accident prevention, not encryption. Access control is the vault ACL.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from sentinelx.core.enums import AuditActor, QuarantineStatus
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.quarantine import win32fs
from sentinelx.quarantine.win32fs import QuarantineError, SourceHandle
from sentinelx.scanner.exclusions import norm_path
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.db import Database
from sentinelx.storage.orm import QuarantineItem

log = logging.getLogger(__name__)

CHUNK = 1024 * 1024
MAGIC = b"SXQ1"
KEY_BYTES = 32
MAX_ZONE_BYTES = 64 * 1024
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$", re.IGNORECASE)


@dataclass(frozen=True)
class QItem:
    id: int
    vault_id: str
    original_path: str
    sha256: str
    size: int
    status: QuarantineStatus
    quarantined_at: str
    reason: str | None
    verdict_id: int | None
    duplicate_of: int | None
    restored_at: str | None
    restore_target: str | None
    has_zone_identifier: bool
    error_detail: str | None
    deleted_at: str | None = None


def _xor(data: bytes, key: bytes, offset: int) -> bytes:
    """XOR with the repeating key, aligned to the absolute stream offset (fast big-int XOR)."""
    if not data:
        return b""
    n = len(key)
    start = offset % n
    ks = (key * ((len(data) + start) // n + 1))[start:start + len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(ks, "little")).to_bytes(len(data), "little")


def _same_path(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a)) == os.path.normcase(str(b))


class QuarantineVault:
    def __init__(self, vault_dir: Path, db: Database, audit: AuditLog, *, protected_root: Path | None = None) -> None:
        self._dir = vault_dir
        # Sentinel X's own data folder (rules, reports, database, signatures): never a quarantine
        # source and never a restore target. Defaults to the vault folder alone.
        self._protected = protected_root or vault_dir
        self._db = db
        self._audit = audit
        self._lock = threading.Lock()
        self._last_own_change = time.monotonic()  # vault folder changes made by Sentinel X
        self._ready = False
        self._problem = ""
        self._prepare()

    # ---------------- readiness ----------------
    def _prepare(self) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            sid = win32fs.current_user_sid()
            if not win32fs.dacl_is_private(win32fs.read_dacl_sddl(self._dir), sid):
                win32fs.harden_directory(self._dir, sid)
            if not win32fs.dacl_is_private(win32fs.read_dacl_sddl(self._dir), sid):
                raise QuarantineError("vault ACL not private", user_message="隔離區權限無法限制為只有目前使用者。")
            self._reconcile()
            self._ready, self._problem = True, ""
        except (OSError, QuarantineError) as exc:
            self._ready = False
            self._problem = exc.user_message if isinstance(exc, QuarantineError) else f"隔離區無法使用：{exc}"
            log.error("vault not ready", extra={"ctx": {"dir": str(self._dir), "problem": self._problem}})

    def _reconcile(self) -> None:
        """Repair what a crash or forced exit could leave behind (B2, ENGINEERING_AUDIT.md).

        - `*.part` files are Sentinel X's own incomplete obfuscated copies: removed.
        - A QUARANTINED item whose vault object is missing gets an error note.
        - A QUARANTINED item whose original still exists with the same hash (crash between
          recording and deleting) becomes RETAINED_ERROR, so it is not shown as contained.
        """
        for part in self._dir.glob("*.part"):
            try:
                part.unlink()
            except OSError:
                log.warning("cannot remove partial vault file", extra={"ctx": {"file": part.name}})
        changed: list[tuple[int, str, str]] = []
        with self._db.session() as s:
            for q in s.scalars(select(QuarantineItem).where(
                    QuarantineItem.status == QuarantineStatus.QUARANTINED.value)):
                if not (self._dir / f"{q.vault_id}.sxq").is_file():
                    if q.error_detail != "隔離檔案遺失":
                        q.error_detail = "隔離檔案遺失"
                        changed.append((q.id, "missing_object", q.original_path))
                    continue
                orig = Path(q.original_path)
                try:
                    same = orig.is_file() and orig.stat().st_size == q.size and _sha256(orig) == q.sha256
                except OSError:
                    same = False
                if same:
                    q.status = QuarantineStatus.RETAINED_ERROR.value
                    q.error_detail = "原始檔案仍存在（隔離未完成，可能是程式中途結束）"
                    changed.append((q.id, "original_present", q.original_path))
        for item_id, kind, path in changed:
            self._audit.record("QUARANTINE_RECONCILE", subject=path, detail={"item_id": item_id, "issue": kind})

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def problem(self) -> str:
        return self._problem

    @property
    def directory(self) -> Path:
        return self._dir

    def _object(self, vault_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", vault_id):
            raise QuarantineError(f"bad vault id {vault_id!r}", user_message="隔離紀錄已損壞。")
        return self._dir / f"{vault_id}.sxq"

    # ---------------- listing ----------------
    @staticmethod
    def _row(q: QuarantineItem) -> QItem:
        return QItem(q.id, q.vault_id, q.original_path, q.sha256, q.size, QuarantineStatus(q.status),
                     q.confirmed_by_user_at, q.reason, q.verdict_id, q.duplicate_of, q.restored_at,
                     q.restore_target, bool(q.zone_identifier), q.error_detail, q.deleted_at)

    def items(self) -> list[QItem]:
        with self._db.session() as s:
            return [self._row(q) for q in s.scalars(select(QuarantineItem).order_by(QuarantineItem.id.desc()))]

    def get(self, item_id: int) -> QItem | None:
        with self._db.session() as s:
            q = s.get(QuarantineItem, item_id)
            return self._row(q) if q else None

    def active_for(self, sha256: str, path: str) -> QItem | None:
        with self._db.session() as s:
            for q in s.scalars(select(QuarantineItem).where(QuarantineItem.sha256 == sha256,
                                                            QuarantineItem.status == QuarantineStatus.QUARANTINED.value)):
                if norm_path(q.original_path) == norm_path(path):
                    return self._row(q)
        return None

    # ---------------- intake ----------------
    def own_change_age(self) -> float:
        """Seconds since Sentinel X last changed the vault folder (0 while it is changing it)."""
        return 0.0 if self._lock.locked() else time.monotonic() - self._last_own_change

    def quarantine(self, path: Path, expected_sha256: str, *, verdict_id: int | None, reason: str) -> QItem:
        if not self._ready:
            raise QuarantineError("vault not ready", user_message=self._problem or "隔離區無法使用。")
        with self._lock:
            try:
                return self._quarantine(Path(os.path.abspath(path)), expected_sha256.lower(), verdict_id, reason)
            finally:
                self._last_own_change = time.monotonic()

    def _quarantine(self, path: Path, expected: str, verdict_id: int | None, reason: str) -> QItem:
        if not _same_path(Path(os.path.realpath(path)), path):
            raise QuarantineError("path goes through a link", user_message="檔案路徑經過符號連結或交接點，為了安全不會隔離。")
        if self._dir in path.parents or _same_path(path.parent, self._dir):
            raise QuarantineError("inside vault", user_message="不能隔離隔離區內的檔案。")
        if self._protected in path.parents:
            raise QuarantineError("inside data folder", user_message="這是 Sentinel X 自己的資料檔案（規則、報告、資料庫），不能隔離。")
        if self.active_for(expected, str(path)) is not None:
            raise QuarantineError("duplicate", user_message="這個檔案（同一路徑、同一 SHA-256）已在隔離區中。")

        zone: str | None = None
        try:
            with open(f"{path}:Zone.Identifier", "rb") as zf:
                zone = zf.read(MAX_ZONE_BYTES).decode("utf-8", "replace")
        except OSError:
            zone = None
        try:
            mtime: str | None = _iso(os.stat(path).st_mtime)
        except OSError:
            mtime = None

        vault_id = uuid.uuid4().hex
        key = os.urandom(KEY_BYTES)
        part = self._dir / f"{vault_id}.part"
        final = self._object(vault_id)

        with SourceHandle(path) as src:
            # Re-check on the handle itself: a parent folder could have been swapped for a
            # junction after the realpath check above (B1, ENGINEERING_AUDIT.md).
            if not _same_path(Path(src.final_path()), path):
                raise QuarantineError("final path mismatch",
                                      user_message="檔案的實際位置與預期不同（路徑中途被改成連結），已取消隔離。")
            if src.links > 1:
                raise QuarantineError("hard links", user_message="這個檔案有多個硬連結，移除一個路徑無法完全隔離，已取消。")
            h = hashlib.sha256()
            size = 0
            try:
                with src.reader() as r, open(part, "xb") as out:
                    out.write(MAGIC)
                    while chunk := r.read(CHUNK):
                        h.update(chunk)
                        out.write(_xor(chunk, key, size))
                        size += len(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                actual = h.hexdigest()
                if actual != expected:
                    raise QuarantineError("hash mismatch", user_message="檔案內容在掃描後已被修改，請重新掃描後再隔離。")
                os.replace(part, final)
                if self._decode_hash(final, key) != expected:
                    final.unlink()
                    raise QuarantineError("vault write verification failed", user_message="寫入隔離區後驗證失敗，已取消。")
            except BaseException:
                if part.exists():
                    part.unlink()
                raise

            dup = self._duplicate_of(expected)
            item_id = self._insert(vault_id, path, expected, size, verdict_id, reason, zone, key, mtime,
                                   src.attributes, dup)
            try:
                src.mark_for_deletion()
            except QuarantineError as exc:
                self._mark_error(item_id, exc.user_message)
                raise QuarantineError(str(exc), user_message=f"已備份到隔離區，但無法移除原始檔案：{exc.user_message}") from exc

        if path.exists():
            self._mark_error(item_id, "原始檔案在移除後仍然存在")
            raise QuarantineError("original still present", user_message="已備份到隔離區，但原始檔案仍然存在。")
        item = self.get(item_id)
        assert item is not None
        log.info("quarantined", extra={"ctx": {"item": item_id, "sha256": expected}})
        return item

    def _duplicate_of(self, sha256: str) -> int | None:
        with self._db.session() as s:
            q = s.scalars(select(QuarantineItem).where(QuarantineItem.sha256 == sha256)
                          .order_by(QuarantineItem.id).limit(1)).first()
            return q.id if q else None

    def _insert(self, vault_id: str, path: Path, sha: str, size: int, verdict_id: int | None, reason: str,
                zone: str | None, key: bytes, mtime: str | None, attrs: int, dup: int | None) -> int:
        audit_id = self._audit.record(
            "QUARANTINE", actor=AuditActor.USER, subject=str(path),
            detail={"vault_id": vault_id, "original_path": str(path), "sha256": sha, "size": size,
                    "verdict_id": verdict_id, "reason": reason, "duplicate_of": dup},
        )
        with self._db.session() as s:
            q = QuarantineItem(
                vault_id=vault_id, original_path=str(path), sha256=sha, size=size, verdict_id=verdict_id,
                confirmed_by_user_at=utc_now_iso(), status=QuarantineStatus.QUARANTINED.value,
                zone_identifier=zone, xor_key=key.hex(), duplicate_of=dup, original_mtime=mtime,
                original_attributes=attrs, reason=reason, audit_entry_id=audit_id,
            )
            s.add(q)
            s.flush()
            return q.id

    def _mark_error(self, item_id: int, detail: str) -> None:
        with self._db.session() as s:
            q = s.get(QuarantineItem, item_id)
            if q is not None:
                q.status = QuarantineStatus.RETAINED_ERROR.value
                q.error_detail = detail
        self._audit.record("QUARANTINE_ERROR", subject=str(item_id), detail={"error": detail})

    # ---------------- integrity ----------------
    def _decode_hash(self, obj: Path, key: bytes) -> str:
        h = hashlib.sha256()
        with open(obj, "rb") as f:
            if f.read(len(MAGIC)) != MAGIC:
                raise QuarantineError("bad magic", user_message="隔離檔案格式不正確。")
            off = 0
            while chunk := f.read(CHUNK):
                h.update(_xor(chunk, key, off))
                off += len(chunk)
        return h.hexdigest()

    def verify(self, item_id: int) -> tuple[bool, str]:
        """Re-hash the stored object. Returns (ok, explanation)."""
        with self._db.session() as s:
            q = s.get(QuarantineItem, item_id)
            if q is None:
                return False, "找不到隔離紀錄。"
            if q.status != QuarantineStatus.QUARANTINED.value and q.status != QuarantineStatus.RETAINED_ERROR.value:
                return False, "此項目已不在隔離區中。"
            vault_id, key, sha = q.vault_id, bytes.fromhex(q.xor_key or ""), q.sha256
        obj = self._object(vault_id)
        if not obj.is_file():
            return False, "隔離檔案不存在。"
        try:
            actual = self._decode_hash(obj, key)
        except (OSError, QuarantineError) as exc:
            return False, f"無法讀取隔離檔案：{exc}"
        if actual != sha:
            return False, f"完整性驗證失敗：雜湊 {actual} 與紀錄 {sha} 不符。"
        return True, "完整性驗證通過。"

    def _authorized(self, q: QuarantineItem) -> bool:
        if q.audit_entry_id is None:
            return False
        entry = self._audit.entry(q.audit_entry_id)
        if entry is None:
            return False
        action, d = entry
        return (action == "QUARANTINE" and d.get("vault_id") == q.vault_id and d.get("sha256") == q.sha256
                and d.get("original_path") == q.original_path)

    # ---------------- restore ----------------
    def validate_target(self, target: Path) -> Path:
        t = Path(target)
        if not t.is_absolute():
            raise QuarantineError("relative", user_message="還原路徑必須是完整路徑。")
        s = str(t)
        if ":" in s[2:] or "?" in s or "*" in s:
            raise QuarantineError("ads/wildcard", user_message="還原路徑格式不正確。")
        if _RESERVED.match(t.name) or not t.name or t.name in (".", ".."):
            raise QuarantineError("reserved", user_message="還原檔名不合法。")
        t = Path(os.path.abspath(s))
        parent = t.parent
        if not parent.is_dir():
            raise QuarantineError("no parent", user_message="還原目標資料夾不存在。")
        if not _same_path(Path(os.path.realpath(parent)), parent):
            raise QuarantineError("parent is link", user_message="還原目標資料夾經過符號連結或交接點，為了安全不允許。")
        if _same_path(parent, self._dir) or self._dir in parent.parents:
            raise QuarantineError("inside vault", user_message="不能還原到隔離區內。")
        if _same_path(parent, self._protected) or self._protected in parent.parents:
            raise QuarantineError("inside data folder", user_message="不能還原到 Sentinel X 的資料資料夾內。")
        if os.path.lexists(t):
            raise QuarantineError("exists", user_message="目標位置已有檔案，為避免覆蓋，請選擇其他位置。")
        return t

    # ---------------- permanent delete (user only) ----------------
    def delete(self, item_id: int, reason: str) -> QItem:
        """Permanently delete one quarantined item's stored copy. Only ever called after the
        user confirmed it; nothing in Sentinel X deletes automatically. The record and the audit
        entry stay, so the history (path, SHA-256, reason) is kept."""
        try:
            with self._lock:
                return self._delete(item_id, reason)
        finally:
            self._last_own_change = time.monotonic()

    def _delete(self, item_id: int, reason: str) -> QItem:
        with self._db.session() as s:
            q = s.get(QuarantineItem, item_id)
            if q is None:
                raise QuarantineError("missing", user_message="找不到隔離紀錄。")
            if q.status != QuarantineStatus.QUARANTINED.value:
                raise QuarantineError("not quarantined", user_message="只有隔離中的項目可以永久刪除。")
            vault_id, sha, original = q.vault_id, q.sha256, q.original_path
        obj = self._object(vault_id)
        try:
            obj.unlink()
            note = None
        except FileNotFoundError:
            note = "隔離檔案原本就不存在"
        except OSError as exc:
            raise QuarantineError(str(exc), user_message=f"無法刪除隔離檔案：{exc.strerror or exc}") from exc
        with self._db.session() as s:
            q = s.get(QuarantineItem, item_id)
            q.status = QuarantineStatus.DELETED.value
            q.deleted_at = utc_now_iso()
            q.error_detail = note
        self._audit.record("QUARANTINE_DELETE", actor=AuditActor.USER, subject=original,
                           detail={"item_id": item_id, "vault_id": vault_id, "sha256": sha, "reason": reason})
        log.info("quarantine item deleted", extra={"ctx": {"item": item_id, "sha256": sha}})
        item = self.get(item_id)
        assert item is not None
        return item

    def restore(self, item_id: int, target: Path | None = None) -> QItem:
        try:
            return self._restore_locked(item_id, target)
        finally:
            self._last_own_change = time.monotonic()

    def _restore_locked(self, item_id: int, target: Path | None) -> QItem:
        with self._lock:
            with self._db.session() as s:
                q = s.get(QuarantineItem, item_id)
                if q is None:
                    raise QuarantineError("missing", user_message="找不到隔離紀錄。")
                if q.status != QuarantineStatus.QUARANTINED.value:
                    raise QuarantineError("not quarantined", user_message="只有隔離中的項目可以還原。")
                if not self._authorized(q):
                    raise QuarantineError("audit mismatch", user_message="隔離紀錄與稽核紀錄不符，可能遭到竄改，拒絕還原。")
                vault_id, key, sha = q.vault_id, bytes.fromhex(q.xor_key or ""), q.sha256
                zone, original = q.zone_identifier, q.original_path
            dest = self.validate_target(Path(target) if target else Path(original))
            obj = self._object(vault_id)
            tmp = dest.parent / f".sxrestore-{uuid.uuid4().hex}.tmp"
            h = hashlib.sha256()
            try:
                with open(obj, "rb") as f, open(tmp, "xb") as out:
                    if f.read(len(MAGIC)) != MAGIC:
                        raise QuarantineError("bad magic", user_message="隔離檔案格式不正確。")
                    off = 0
                    while chunk := f.read(CHUNK):
                        plain = _xor(chunk, key, off)
                        h.update(plain)
                        out.write(plain)
                        off += len(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                if h.hexdigest() != sha:
                    raise QuarantineError("integrity", user_message="完整性驗證失敗：隔離檔案已被變更，拒絕還原。")
                os.rename(tmp, dest)  # never overwrites on Windows
            except FileExistsError as exc:
                raise QuarantineError("exists", user_message="目標位置已有檔案，未覆蓋。") from exc
            except FileNotFoundError as exc:
                raise QuarantineError("vault object missing", user_message="隔離檔案不存在。") from exc
            finally:
                if tmp.exists():
                    tmp.unlink()
            if zone:
                try:
                    with open(f"{dest}:Zone.Identifier", "w", encoding="utf-8") as zf:
                        zf.write(zone)
                except OSError:
                    log.warning("could not restore Zone.Identifier", extra={"ctx": {"target": str(dest)}})
            # Record first, then remove the vault object (B3): a crash in between leaves an extra
            # obfuscated copy, never a restored file with a QUARANTINED record.
            with self._db.session() as s:
                q = s.get(QuarantineItem, item_id)
                q.status = QuarantineStatus.RESTORED.value
                q.restored_at = utc_now_iso()
                q.restore_target = str(dest)
            self._audit.record("RESTORE", actor=AuditActor.USER, subject=str(dest),
                               detail={"item_id": item_id, "vault_id": vault_id, "sha256": sha,
                                       "original_path": original})
            try:
                obj.unlink()
            except OSError as exc:
                with self._db.session() as s:
                    s.get(QuarantineItem, item_id).error_detail = f"已還原，但隔離檔案無法移除：{exc.strerror or exc}"
            item = self.get(item_id)
            assert item is not None
            return item


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
