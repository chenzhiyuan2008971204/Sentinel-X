"""Windows file-system primitives for the quarantine vault (ctypes, no extra dependencies).

- `SourceHandle` opens the file to quarantine ONCE with
  GENERIC_READ | DELETE, share mode READ only, and FILE_FLAG_OPEN_REPARSE_POINT. While it is
  open nobody else can write, rename or delete the file, and a symlink/junction is opened as
  itself (then refused) instead of being followed. Hashing, copying and deleting all go
  through this one handle, so the file that was verified is exactly the file that is removed
  (no check-then-use race on the path).
- Vault ACL: inheritance removed, a single full-control ACE for the current user SID.
  Verified by reading the DACL back as SDDL (locale independent).
"""

from __future__ import annotations

import ctypes
import msvcrt
import os
import re
import subprocess
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import BinaryIO

from sentinelx.core.errors import SentinelXError

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
DELETE = 0x00010000
FILE_SHARE_READ = 0x1
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_DISPOSITION_INFO_CLASS = 4
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
_CREATE_NO_WINDOW = 0x08000000

_ERRORS = {
    2: "找不到檔案",
    3: "找不到路徑",
    5: "存取被拒（權限不足或檔案為唯讀／受保護）",
    32: "檔案正在被其他程式使用",
    33: "檔案的一部分被其他程式鎖定",
}


class QuarantineError(SentinelXError):
    user_message = "隔離作業失敗，原始檔案未被變更。"


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD)]


_k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)]
_k32.GetFileInformationByHandle.restype = wintypes.BOOL
_k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_k32.SetFileInformationByHandle.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
_k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD


def _strip_extended(p: str) -> str:
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    return p[4:] if p.startswith("\\\\?\\") else p


def _err(prefix: str) -> QuarantineError:
    code = ctypes.get_last_error()
    return QuarantineError(f"{prefix}: WinError {code}", user_message=f"{prefix}：{_ERRORS.get(code, f'系統錯誤 {code}')}。")


class SourceHandle:
    """An open, locked handle on the file being quarantined. Use as a context manager."""

    def __init__(self, path: Path) -> None:
        h = _k32.CreateFileW(str(path), GENERIC_READ | DELETE, FILE_SHARE_READ, None, OPEN_EXISTING,
                             FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, None)
        if h == INVALID_HANDLE_VALUE or h is None:
            raise _err("無法開啟檔案")
        self._h = h
        self._fd: int | None = None
        self._delete_requested = False
        info = _BY_HANDLE_FILE_INFORMATION()
        if not _k32.GetFileInformationByHandle(h, ctypes.byref(info)):
            self.close()
            raise _err("無法讀取檔案資訊")
        self.attributes = int(info.dwFileAttributes)
        self.size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
        self.links = int(info.nNumberOfLinks)
        if self.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            self.close()
            raise QuarantineError("reparse point", user_message="這是符號連結或交接點，為了安全不會隔離。")
        if self.attributes & FILE_ATTRIBUTE_DIRECTORY:
            self.close()
            raise QuarantineError("directory", user_message="只能隔離檔案，不能隔離資料夾。")

    def final_path(self) -> str:
        """The path the OS actually opened (all links in the parents resolved)."""
        buf = ctypes.create_unicode_buffer(32768)
        n = _k32.GetFinalPathNameByHandleW(self._h, buf, len(buf), 0)
        if n == 0 or n >= len(buf):
            raise _err("無法確認檔案的實際位置")
        return _strip_extended(buf.value)

    def reader(self) -> BinaryIO:
        """A file object reading through the same handle (the handle stays owned by this object)."""
        if self._fd is None:
            self._fd = msvcrt.open_osfhandle(self._h, os.O_RDONLY | os.O_BINARY)
        return os.fdopen(self._fd, "rb", closefd=False)

    def mark_for_deletion(self) -> None:
        """Delete exactly this file (by handle) when the handle closes."""
        flag = ctypes.c_ubyte(1)
        if not _k32.SetFileInformationByHandle(self._h, FILE_DISPOSITION_INFO_CLASS, ctypes.byref(flag), 1):
            raise _err("無法移除原始檔案")
        self._delete_requested = True

    def close(self) -> None:
        if self._h is None:
            return
        if self._fd is not None:
            os.close(self._fd)  # also closes the OS handle
        else:
            _k32.CloseHandle(self._h)
        self._h = None
        self._fd = None

    def __enter__(self) -> SourceHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ---------------- ACL ----------------
_SID_RE = re.compile(r"S-1-\d+(?:-\d+)+")
_ACE_RE = re.compile(r"\(([^)]*)\)")


def current_user_sid() -> str:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, timeout=30,
                         creationflags=_CREATE_NO_WINDOW).stdout.decode("mbcs", "replace")
    m = _SID_RE.search(out)
    if not m:
        raise QuarantineError(f"cannot determine user SID: {out!r}", user_message="無法取得目前使用者的安全識別碼。")
    return m.group(0)


def read_dacl_sddl(path: Path) -> str:
    fd, tmp = tempfile.mkstemp(prefix="sx-acl-", suffix=".txt")
    os.close(fd)
    try:
        cp = subprocess.run(["icacls", str(path), "/save", tmp], capture_output=True, timeout=30,
                            creationflags=_CREATE_NO_WINDOW)
        if cp.returncode != 0:
            raise QuarantineError(f"icacls /save failed ({cp.returncode})", user_message="無法讀取隔離區的權限設定。")
        text = Path(tmp).read_bytes().decode("utf-16-le", "replace")
    finally:
        os.remove(tmp)
    line = next((ln for ln in text.splitlines() if ln.startswith("D:")), "")
    return line.strip()


def dacl_is_private(sddl: str, sid: str) -> bool:
    """Protected DACL (no inheritance) whose every ACE belongs to `sid`."""
    if not sddl.startswith("D:P"):
        return False
    aces = _ACE_RE.findall(sddl)
    return bool(aces) and all(a.split(";")[-1] == sid and a.split(";")[0] == "A" for a in aces)


def harden_directory(path: Path, sid: str) -> None:
    """Make `sid` the only principal with access (folder and everything in it).

    1. `/reset /T` drops every explicit ACE (whatever principal, however it is abbreviated in
       SDDL, e.g. `WD` for Everyone) on the folder and its contents.
    2. `/inheritance:r /grant:r *SID:(OI)(CI)F` cuts inheritance from the parent and grants the
       user full control, inherited by all vault objects.
    """
    for args in (["/reset", "/T", "/Q"], ["/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"]):
        cp = subprocess.run(["icacls", str(path), *args], capture_output=True, timeout=120,
                            creationflags=_CREATE_NO_WINDOW)
        if cp.returncode != 0:
            raise QuarantineError(f"icacls {args[0]} failed ({cp.returncode}): {cp.stderr!r}",
                                  user_message="無法設定隔離區權限。")
