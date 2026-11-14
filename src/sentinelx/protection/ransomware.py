"""Ransomware warning: notices the typical pattern of files being encrypted, finds the programs
writing the most, and lets the user stop them (never automatically).

What is counted, inside the user's folders (Documents, Desktop, Pictures, Videos, Music,
Downloads, OneDrive), over the last 20 seconds:
- documents renamed to an unusual extension (report.docx -> report.docx.locked)
- new files named after a document plus an extra extension, while documents disappear
  (encrypted copy written, original deleted)
- many existing documents modified
- decoy files (optional, see Decoys) changed, renamed or deleted: no ordinary program touches them

Limits (stated in the UI): a warning comes after some files were already changed; programs that
encrypt slowly or keep extensions stay under the thresholds; the writer is found by comparing
write counters of processes, which needs the process to be readable by this user (an
administrator process may not be) and may also list a busy legitimate program.
"""

from __future__ import annotations

import collections
import hashlib
import logging
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import psutil

log = logging.getLogger(__name__)
WINDOW_S = 20.0
COOLDOWN_S = 600.0
RENAMED_MIN = 10  # documents renamed to an unusual extension
REPLACED_MIN = 10  # odd new copies written + documents deleted
MODIFIED_MIN = 150  # existing documents modified (weaker: also big copy/sync jobs)
DOC_SUFFIXES = frozenset({
    ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods",
    ".odp", ".csv", ".md", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".webp", ".raw",
    ".cr2", ".nef", ".psd", ".ai", ".svg", ".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mov", ".avi", ".mkv",
    ".wmv", ".zip", ".7z", ".rar", ".pst", ".ost", ".one", ".accdb", ".mdb", ".sql", ".sqlite", ".db", ".kdbx",
    ".py", ".js", ".java", ".c", ".cpp", ".cs", ".html", ".css", ".json", ".xml", ".key", ".pages", ".numbers",
})
# Ordinary temporary names editors use while saving (Word's ~$x.docx, x.docx.tmp, ...)
_TEMP_SUFFIXES = frozenset({".tmp", ".temp", ".bak", ".crdownload", ".part", ".partial", ".download", ".lock",
                            ".swp", ".~tmp", ".wbk", ".asd"})
DECOY_DIR = "!!SentinelX 防勒索誘餌（請勿修改）"
KNOWN_FOLDERS = {
    "Pictures": uuid.UUID("33E28130-4E1E-4676-835A-98395C3BC3BB"),
    "Videos": uuid.UUID("18989B1D-99B5-455B-841C-AB7C74E4DDFC"),
    "Music": uuid.UUID("4BD8D571-6D19-48D3-BE97-422220080E43"),
}
NEVER_STOP = frozenset({"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                        "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "memcompression",
                        "msmpeng.exe", "securityhealthservice.exe", "searchindexer.exe", "explorer.exe"})


def user_folders() -> list[Path]:
    from sentinelx.protection import locations

    out = [locations.documents(), locations.desktop(), locations.downloads()]
    out += [locations.known_folder(f) for f in KNOWN_FOLDERS.values()]
    one = os.environ.get("OneDrive")
    if one:
        out.append(Path(one))
    seen, result = set(), []
    for p in out:
        if p is not None and os.path.normcase(str(p)) not in seen:
            seen.add(os.path.normcase(str(p)))
            result.append(p)
    return result


def _suffix(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def _is_doc(name: str) -> bool:
    return _suffix(name) in DOC_SUFFIXES and not name.startswith("~$")


def _odd_copy_of_doc(name: str) -> bool:
    """report.docx.locked, photo.jpg.enc, x.pdf.[id].crypt -> True (a document name plus more)."""
    stem, ext = os.path.splitext(name)
    if not ext or ext.lower() in DOC_SUFFIXES or ext.lower() in _TEMP_SUFFIXES:
        return False
    while stem:
        stem, inner = os.path.splitext(stem)
        if inner.lower() in DOC_SUFFIXES:
            return True
        if not inner:
            return False
    return False


@dataclass(frozen=True)
class Writer:
    pid: int
    name: str
    exe: str
    written_mb: float


@dataclass
class Alert:
    level: str  # "bad" strong pattern / decoy touched, "warn" many modifications only
    reason: str
    examples: list[str]
    writers: list[Writer] = field(default_factory=list)
    at: float = 0.0


class WriteSampler:
    """Remembers how much every process has written, to find who wrote most since then."""

    def __init__(self, procs: Callable[[], list[tuple[int, str, str, int]]] | None = None) -> None:
        self._procs = procs or self._read
        self._prev: dict[int, tuple[str, str, int]] = {}  # the older of the last two snapshots
        self._last: dict[int, tuple[str, str, int]] = {}
        self._own = {os.getpid()}

    @staticmethod
    def _read() -> list[tuple[int, str, str, int]]:
        out = []
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                io = p.io_counters()
                # Protected or just-ended processes come without some fields (seen on the user's
                # computer: every snapshot failed on a missing "name", so writers were ranked by
                # their total since start instead of the last half minute).
                out.append((p.pid, p.info.get("name") or "", p.info.get("exe") or "", int(io.write_bytes)))
            except (psutil.Error, OSError, AttributeError, KeyError):
                continue
        return out

    def snapshot(self) -> None:
        try:
            self._own = {os.getpid(), *(c.pid for c in psutil.Process().children(recursive=True))}
        except psutil.Error:
            pass
        self._prev, self._last = self._last, {pid: (name, exe, wb) for pid, name, exe, wb in self._procs()}

    def top(self, n: int = 3, min_mb: float = 1.0) -> list[Writer]:
        rows = []
        for pid, name, exe, wb in self._procs():
            if pid in self._own or name.lower() in ("system", "registry", "memcompression"):
                continue
            before = self._prev.get(pid) or self._last.get(pid)
            delta = wb - (before[2] if before and before[0] == name else 0)
            if delta >= min_mb * 1024 * 1024:
                rows.append(Writer(pid, name, exe, round(delta / 1024 / 1024, 1)))
        rows.sort(key=lambda w: -w.written_mb)
        return rows[:n]


class RansomwareDetector:
    def __init__(self, roots: Callable[[], list[Path]] | None = None, *, clock: Callable[[], float] = time.monotonic,
                 sampler: WriteSampler | None = None, decoys: Callable[[], set[str]] = set,
                 decoy_changed: Callable[[str], bool] = lambda _p: True) -> None:
        self._roots_fn = roots or (lambda: user_folders())  # looked up late (tests patch it)
        self._roots: list[str] = []
        self._roots_at = -1e9
        self._clock = clock
        self.sampler = sampler or WriteSampler()
        self._sampled_at = -1e9
        self.sample_every_s = 15.0
        self._decoys = decoys
        self._decoy_changed = decoy_changed  # content check: attribute-only changes (OneDrive) do not count
        self._events: collections.deque[tuple[float, str, str]] = collections.deque()  # (t, kind, path)
        self._last_alert = -1e9
        self._lock = threading.Lock()
        self.alert: Alert | None = None  # latest, shown on the protection page until dismissed

    def _in_roots(self, path: str) -> bool:
        now = self._clock()
        if now - self._roots_at > 300:
            self._roots = [os.path.normcase(str(r)).rstrip("\\/") + os.sep for r in self._roots_fn()]
            self._roots_at = now
        n = os.path.normcase(path)
        return any(n.startswith(r) for r in self._roots)

    def event(self, kind: str, path: str, dest: str | None = None) -> Alert | None:
        """Feed one file event; returns an Alert when the pattern is reached (at most every 10 min)."""
        decoy_hit = os.path.normcase(path) in self._decoys() or (dest and os.path.normcase(dest) in self._decoys())
        if not decoy_hit and not self._in_roots(dest or path):
            return None
        now = self._clock()
        with self._lock:
            if kind == "moved" and dest:
                if _is_doc(os.path.basename(path)) and _odd_copy_of_doc(os.path.basename(dest)):
                    self._events.append((now, "renamed", dest))
            elif kind == "created" and _odd_copy_of_doc(os.path.basename(path)):
                self._events.append((now, "odd_new", path))
            elif kind == "deleted" and _is_doc(os.path.basename(path)):
                self._events.append((now, "deleted", path))
            elif kind == "modified" and _is_doc(os.path.basename(path)):
                self._events.append((now, "modified", path))
            if decoy_hit and kind != "created" and self._decoy_changed(path):
                return self._decoy_alert(path, now)
            while self._events and now - self._events[0][0] > WINDOW_S:
                self._events.popleft()
            return self._check(now)

    def tick(self) -> None:
        """Called every few seconds: remembers write counters (about 50 ms) every 15 s, so the
        programs that wrote most during an alert can be named."""
        now = self._clock()
        if now - self._sampled_at >= self.sample_every_s:
            self._sampled_at = now
            try:
                self.sampler.snapshot()
            except Exception:  # noqa: BLE001
                log.exception("write sampling failed")

    def _decoy_alert(self, path: str, now: float) -> Alert | None:
        if now - self._last_alert < 60:  # a decoy hit is strong: repeat sooner, but not per file
            return None
        return self._raise("bad", "防勒索誘餌檔被修改了：一般程式不會碰這些檔案，很可能是勒索病毒正在加密你的檔案。",
                           [path], now)

    def _check(self, now: float) -> Alert | None:
        if now - self._last_alert < COOLDOWN_S:
            return None
        kinds: dict[str, set[str]] = collections.defaultdict(set)
        for _t, k, p in self._events:
            kinds[k].add(p)
        renamed, odd, deleted, modified = (len(kinds[k]) for k in ("renamed", "odd_new", "deleted", "modified"))
        if renamed >= RENAMED_MIN:
            return self._raise("bad", f"{WINDOW_S:.0f} 秒內有 {renamed} 個文件被改成奇怪的副檔名（勒索病毒加密檔案的典型做法）。",
                               sorted(kinds["renamed"])[:5], now)
        if odd >= REPLACED_MIN and deleted >= REPLACED_MIN:
            return self._raise("bad", f"{WINDOW_S:.0f} 秒內出現 {odd} 個「文件名稱加上奇怪副檔名」的新檔案，"
                                      f"同時有 {deleted} 個文件被刪除（勒索病毒加密後刪掉原檔的典型做法）。",
                               sorted(kinds["odd_new"])[:5], now)
        if modified >= MODIFIED_MIN:
            return self._raise("warn", f"{WINDOW_S:.0f} 秒內有 {modified} 個文件被修改。如果你沒有在大量處理檔案"
                                       "（例如同步、備份、批次轉檔），可能是勒索病毒。", sorted(kinds["modified"])[:5], now)
        return None

    def _raise(self, level: str, reason: str, examples: list[str], now: float) -> Alert:
        self._last_alert = now
        self._events.clear()
        try:
            writers = self.sampler.top()
        except Exception:  # noqa: BLE001
            writers = []
        self.alert = Alert(level, reason, examples, writers, now)
        return self.alert


def stop_process(pid: int, expected_name: str) -> str:
    """Stop one process the user chose from an alert. Refuses Windows' own critical processes and
    a different process that got the same number meanwhile."""
    if expected_name.lower() in NEVER_STOP:
        raise PermissionError(f"{expected_name} 是 Windows 必要的程式，不能停止。")
    try:
        p = psutil.Process(pid)
        if (p.name() or "").lower() != expected_name.lower():
            return f"{expected_name} 已經結束了。"
        p.kill()
        p.wait(1)  # the page stays responsive; a slow exit is reported as requested
    except psutil.NoSuchProcess:
        return f"{expected_name} 已經結束了。"
    except psutil.AccessDenied as exc:
        raise PermissionError(f"沒有權限停止 {expected_name}（它可能以系統管理員身分執行）。請重新開機或用工作管理員結束它。") from exc
    except psutil.TimeoutExpired:
        return f"已要求停止 {expected_name}。"
    return f"已停止 {expected_name}。"


# ---------------- optional decoy files ----------------
_DECOY_FILES = {
    "!!0 帳戶密碼備份.xlsx": b"PK\x03\x04",
    "!!0 合約掃描.pdf": b"%PDF-1.7\n",
    "!!0 家庭照片.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
    "!!0 報稅資料.docx": b"PK\x03\x04",
}
_README = ("這個資料夾是 Sentinel X 的「防勒索誘餌」。裡面的檔案不是真的文件，一般程式不會去動它們；"
           "如果它們被修改、改名或刪除，Sentinel X 會立刻警告你可能有勒索病毒。\n"
           "請不要修改。不想要的話，在 Sentinel X「即時防護」關掉「放置防勒索誘餌檔」，會自動移除。\n")


class Decoys:
    """Harmless decoy documents in a hidden folder at the top of the user's folders (the name
    starts with "!!" so programs that go through files alphabetically reach it first)."""

    def __init__(self, roots: Callable[[], list[Path]] | None = None) -> None:
        self._roots = roots or (lambda: user_folders())  # looked up late (tests patch it)
        self._paths: set[str] = set()
        self._names: dict[str, str] = {}  # normcase path -> decoy name
        self.placed_at = -1e9

    @staticmethod
    def _content(header: bytes, name: str) -> bytes:
        body = hashlib.sha256(name.encode("utf-8")).digest() * 512  # 16 KB, fixed per name
        return header + body

    def place(self) -> list[Path]:
        made = []
        for root in self._roots():
            if not root.is_dir():
                continue
            d = root / DECOY_DIR
            try:
                d.mkdir(exist_ok=True)
                (d / "說明 README.txt").write_text(_README, encoding="utf-8")
                for name, header in _DECOY_FILES.items():
                    f = d / name
                    if not f.exists():
                        f.write_bytes(self._content(header, name))
                    made.append(f)
                _hide(d)
            except OSError:
                log.warning("cannot place decoys", extra={"ctx": {"folder": str(root)}})
        self._names = {os.path.normcase(str(p)): p.name for p in made}
        self.placed_at = time.monotonic()
        self._paths = set(self._names)
        return made

    def paths(self) -> set[str]:
        """Decoys to watch; empty for 15 s after placing them (their own creation events)."""
        return self._paths if time.monotonic() - self.placed_at > 15 else set()

    def changed(self, path: str) -> bool:
        """True when a decoy is gone or its content differs (not for attribute-only changes)."""
        name = self._names.get(os.path.normcase(path))
        if name is None:
            return False
        try:
            return Path(path).read_bytes() != self._content(_DECOY_FILES[name], name)
        except OSError:
            return True  # deleted, renamed away or locked by the program changing it

    def remove(self) -> int:
        """Remove only Sentinel X's own decoys (checked by content) and the folder if then empty."""
        self._paths, self._names = set(), {}  # stop watching first: removing them is not an attack
        n = 0
        for root in self._roots():
            d = root / DECOY_DIR
            if not d.is_dir() or d.is_symlink():
                continue
            for name, header in _DECOY_FILES.items():
                f = d / name
                try:
                    if f.is_file() and not f.is_symlink() and f.read_bytes() == self._content(header, name):
                        f.unlink()
                        n += 1
                except OSError:
                    continue
            try:
                readme = d / "說明 README.txt"
                if readme.is_file() and readme.read_text(encoding="utf-8") == _README:
                    readme.unlink()
                d.rmdir()  # only when empty: changed files are left for the user to see
            except OSError:
                pass
        return n


def _hide(path: Path) -> None:
    try:
        import ctypes

        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x2)  # FILE_ATTRIBUTE_HIDDEN
    except (OSError, AttributeError):
        pass
