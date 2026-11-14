"""Isolated worker: parse one file with pefile and inspect its signature (or compile YARA test rules), print JSON.

Started by `research.isolation` as `python -I -m sentinelx.research.worker <path> <max_bytes>`
(or `Sentinel X.exe --research-worker ...` when frozen). It never executes the analyzed file.
Before touching the file it puts itself in a Windows job object that caps its memory and
forbids starting child processes, so a hostile file that confuses the parser can at worst
crash or stall this process, which the parent then kills.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

MEMORY_LIMIT = 1024 * 1024 * 1024
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


class _BASIC(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class _EXTENDED(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC), ("IoInfo", ctypes.c_uint64 * 6),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def confine_self(memory_limit: int = MEMORY_LIMIT) -> str | None:
    """Put this process in a job: memory cap, one process only. Returns an error text or None."""
    if sys.platform != "win32":
        return "僅支援 Windows"
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return f"CreateJobObject 失敗（{ctypes.get_last_error()}）"
    info = _EXTENDED()
    info.BasicLimitInformation.LimitFlags = (JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                                             | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    info.BasicLimitInformation.ActiveProcessLimit = 1
    info.ProcessMemoryLimit = memory_limit
    if not k32.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info),
                                       ctypes.sizeof(info)):
        return f"SetInformationJobObject 失敗（{ctypes.get_last_error()}）"
    if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        return f"AssignProcessToJobObject 失敗（{ctypes.get_last_error()}）"
    return None  # the handle stays open for the life of the process on purpose


def inspect(path: Path, max_bytes: int) -> dict[str, Any]:
    from sentinelx.core.serialize import result_to_dict
    from sentinelx.engines.authenticode import inspect_signature
    from sentinelx.engines.pe_static import PEStaticEngine
    from sentinelx.core.models import ScanTarget
    from sentinelx.scanner.walker import is_reparse_point

    st = os.lstat(path)
    if is_reparse_point(st):
        raise ValueError("這是符號連結或交接點，不會跟隨分析。")
    if not path.is_file():
        raise ValueError("不是一般檔案。")
    if st.st_size > max_bytes:
        raise ValueError("檔案超過大小上限。")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    sha = h.hexdigest()
    sig = inspect_signature(path)
    engine = PEStaticEngine(verifier=lambda _p: sig.info())
    pe = engine.analyze(ScanTarget(path, sha, st.st_size))
    return {"sha256": sha, "size": st.st_size, "pe": result_to_dict(pe), "signature": sig.to_dict()}


YARA_COMPILE_FLAG = "--yara-compile"


def compile_check(rule_file: Path) -> dict[str, Any]:
    """Compile YARA rule text (audit R12): a pathological rule can only stall this process."""
    import yara

    from sentinelx.research.yara_lab import compile_test_rules

    _rules, count = compile_test_rules(rule_file.read_text(encoding="utf-8"))
    return {"rule_count": count, "yara_version": yara.YARA_VERSION}


def main(argv: list[str]) -> int:
    started = time.monotonic()
    confine_error = confine_self()
    try:
        if len(argv) == 2 and argv[0] == YARA_COMPILE_FLAG:
            out: dict[str, Any] = {"ok": True, **compile_check(Path(argv[1]))}
        elif len(argv) != 2:
            raise ValueError("用法：worker <path> <max_bytes> | worker --yara-compile <rule_file>")
        else:
            out = {"ok": True, **inspect(Path(argv[0]), int(argv[1]))}
    except Exception as exc:  # noqa: BLE001 - reported to the parent as data
        out = {"ok": False, "error": str(exc) if isinstance(exc, ValueError) else f"{type(exc).__name__}: {exc}"}
    out["confined"] = confine_error is None
    out["confine_error"] = confine_error
    out["duration_ms"] = int((time.monotonic() - started) * 1000)
    data = json.dumps(out, ensure_ascii=False, default=str).encode("utf-8")
    if sys.stdout is not None:
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
    else:
        # Windowed (no console) build: Python may not create sys.stdout even though the parent
        # passed a file handle as standard output. Write to that handle directly (audit R14).
        import os

        os.write(1, data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
