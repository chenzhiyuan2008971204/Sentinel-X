"""Facts about one file that need no parser: hashes, size, times, type by magic bytes, MOTW.

Read-only. The file is opened for reading only and never executed.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.core.cancel import CancelToken
from sentinelx.scanner.walker import is_reparse_point

CHUNK = 1024 * 1024
MAX_MOTW_BYTES = 8192

# (prefix, offset, description). Checked in order; first match wins.
_MAGIC: tuple[tuple[bytes, int, str], ...] = (
    (b"MZ", 0, "Windows 可執行檔或 DLL（MZ/PE）"),
    (b"\x7fELF", 0, "ELF 可執行檔（Linux）"),
    (b"%PDF-", 0, "PDF 文件"),
    (b"PK\x03\x04", 0, "ZIP 壓縮檔（也可能是 Office 文件、JAR、APK）"),
    (b"PK\x05\x06", 0, "ZIP 壓縮檔（空）"),
    (b"Rar!\x1a\x07", 0, "RAR 壓縮檔"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip 壓縮檔"),
    (b"\x1f\x8b", 0, "GZIP 壓縮檔"),
    (b"MSCF", 0, "Microsoft Cabinet 壓縮檔"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE 複合文件（舊版 Office、MSI）"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "Windows 捷徑（LNK）"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG 圖片"),
    (b"\xff\xd8\xff", 0, "JPEG 圖片"),
    (b"GIF8", 0, "GIF 圖片"),
    (b"{\\rtf", 0, "RTF 文件"),
    (b"#!", 0, "指令碼（shebang）"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O 通用檔或 Java class"),
    (b"dex\n", 0, "Android DEX"),
    (b"CD001", 0x8001, "ISO 光碟映像"),
)


@dataclass(frozen=True)
class FileFacts:
    path: Path
    size: int
    md5: str
    sha1: str
    sha256: str
    file_type: str
    modified: str | None
    created: str | None
    motw: dict[str, str] | None  # parsed Zone.Identifier stream, when present


def _iso(ts: float) -> str | None:
    try:
        return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def check_regular_file(path: Path, max_bytes: int) -> os.stat_result:
    st = os.lstat(path)
    if is_reparse_point(st):
        raise ValueError("這是符號連結或交接點，為了安全不會跟隨分析。")
    if not path.is_file():
        raise ValueError("請選擇一般檔案。")
    if st.st_size > max_bytes:
        raise ValueError(f"檔案超過大小上限 {max_bytes // (1024 * 1024)} MB。")
    return st


def detect_type(head: bytes) -> str:
    for magic, off, desc in _MAGIC:
        if head[off:off + len(magic)] == magic:
            return desc
    if not head:
        return "空檔案"
    sample = head[:4096]
    if b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return "文字檔（UTF-8／ASCII）"
        except UnicodeDecodeError:
            return "文字檔（非 UTF-8 編碼）"
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "文字檔（UTF-16）"
    return "未知的二進位格式"


def read_motw(path: Path) -> dict[str, str] | None:
    """Mark-of-the-Web (Zone.Identifier alternate data stream). Attacker-influenced text."""
    try:
        with open(f"{path}:Zone.Identifier", "rb") as f:
            raw = f.read(MAX_MOTW_BYTES)
    except OSError:
        return None
    out: dict[str, str] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() and len(out) < 20:
            out[k.strip()[:64]] = v.strip()[:1000]
    return out


def file_facts(path: Path, max_bytes: int, cancel: CancelToken | None = None) -> FileFacts:
    cancel = cancel or CancelToken()
    st = check_regular_file(path, max_bytes)
    md5, sha1, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()
    head = b""
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            cancel.raise_if_cancelled()
            if len(head) < 0x8010:
                head += chunk[: 0x8010 - len(head)]
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return FileFacts(path, st.st_size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), detect_type(head),
                     _iso(st.st_mtime), _iso(st.st_ctime), read_motw(path))
