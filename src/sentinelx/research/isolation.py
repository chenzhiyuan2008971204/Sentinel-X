"""Run the research worker in a separate process with a timeout and cancellation.

The worker's stdout goes to a temporary file (not a pipe), so a large result can never
deadlock the wait loop. Only JSON comes back; nothing is unpickled.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.core.cancel import CancelToken, ScanCancelled

WORKER_FLAG = "--research-worker"
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
CREATE_NO_WINDOW = 0x08000000


@dataclass(frozen=True)
class WorkerResult:
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0
    confined: bool = False


def worker_command(path: Path, max_bytes: int, *, executable: str | None = None,
                   frozen: bool | None = None) -> list[str]:
    """Fixed argument list: the file path and size limit are the only variable parts."""
    exe = executable or sys.executable
    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    if is_frozen:
        return [exe, WORKER_FLAG, str(path), str(max_bytes)]
    return [exe, "-I", "-m", "sentinelx.research.worker", str(path), str(max_bytes)]


def compile_command(rule_file: Path, *, executable: str | None = None, frozen: bool | None = None) -> list[str]:
    exe = executable or sys.executable
    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    if is_frozen:
        return [exe, WORKER_FLAG, "--yara-compile", str(rule_file)]
    return [exe, "-I", "-m", "sentinelx.research.worker", "--yara-compile", str(rule_file)]


def run_worker(path: Path, max_bytes: int, *, timeout_s: float = 60.0, cancel: CancelToken | None = None,
               command: list[str] | None = None) -> WorkerResult:
    cancel = cancel or CancelToken()
    cmd = command or worker_command(path, max_bytes)
    return _run(cmd, timeout_s, cancel)


def check_yara_compile(source: str, *, timeout_s: float = 30.0, cancel: CancelToken | None = None,
                       command: list[str] | None = None) -> WorkerResult:
    """Compile rule text in the confined worker with a time limit before compiling it here (audit R12)."""
    cancel = cancel or CancelToken()
    with tempfile.TemporaryDirectory(prefix="sx-yara-") as d:
        rule_file = Path(d) / "rules.yar"
        rule_file.write_text(source, encoding="utf-8")
        return _run(command or compile_command(rule_file), timeout_s, cancel)


def _run(cmd: list[str], timeout_s: float, cancel: CancelToken) -> WorkerResult:
    started = time.monotonic()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0)
        try:
            while True:
                try:
                    proc.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if cancel.cancelled:
                    raise ScanCancelled()
                if time.monotonic() - started > timeout_s:
                    return WorkerResult(False, error=f"逾時（{timeout_s:g} 秒），已終止分析程序。",
                                        duration_ms=int((time.monotonic() - started) * 1000))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        ms = int((time.monotonic() - started) * 1000)
        out.seek(0)
        raw = out.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            return WorkerResult(False, error="分析程序輸出過大，已放棄。", duration_ms=ms)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            err.seek(0)
            tail = err.read(4000).decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            return WorkerResult(False, error=f"分析程序異常結束（代碼 {proc.returncode}）{('：' + tail[0]) if tail[0] else ''}",
                                duration_ms=ms)
    if not isinstance(data, dict):
        return WorkerResult(False, error="分析程序回傳格式錯誤。", duration_ms=ms)
    if not data.get("ok"):
        return WorkerResult(False, error=str(data.get("error") or "未知錯誤"), duration_ms=ms,
                            confined=bool(data.get("confined")))
    return WorkerResult(True, data, None, ms, bool(data.get("confined")))
