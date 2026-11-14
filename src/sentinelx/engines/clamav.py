"""ClamAV adapter, `clamscan.exe` backend.

Isolation: clamscan runs as a separate process with an argument list (no shell), a hidden
window, a timeout and cooperative cancellation (the process is killed on cancel).

Error handling rules:
- ClamAV missing, or present without a signature database -> engine unavailable.
- Process crash, unexpected exit code, timeout, unparseable output -> ERROR for the batch.
- A submitted file with no result line -> ERROR for that file (never "no findings").
- `Heuristics.Limits.Exceeded*` means the file was not fully scanned -> ERROR, not a finding.

clamscan reloads its signature database on every start (seconds), so files are scanned in
batches via `--file-list`.

Note: `clamscan --version` reports only the first `--database` given, so the adapter passes
exactly one database directory.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget
from sentinelx.scanner.exclusions import norm_path

log = logging.getLogger(__name__)

ENGINE_NAME = "ClamAV"


def bundled_location() -> Path | None:
    """`<app folder>/clamav/clamscan.exe` in the packaged build (ClamAV ships with the installer)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "clamav" / "clamscan.exe"
    return None


def is_bundled(clamscan: Path | None) -> bool:
    b = bundled_location()
    return clamscan is not None and b is not None and clamscan.resolve() == b.resolve()


def default_locations() -> tuple[Path, ...]:
    """Bundled copy first, then standard install locations from %ProgramFiles% / %ProgramFiles(x86)%."""
    out = [b] if (b := bundled_location()) is not None else []
    for var, fallback in (("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        out.append(Path(os.environ.get(var) or fallback) / "ClamAV" / "clamscan.exe")
    return tuple(out)
_VERSION_RE = re.compile(r"^ClamAV\s+(?P<engine>[0-9][^/\s]*)(?:/(?P<db>\d+)/(?P<date>.+))?$")
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
LIMIT_SIGNATURE_PREFIX = "Heuristics.Limits.Exceeded"


def locate_clamscan(configured: str | None = None) -> Path | None:
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    candidates.extend(default_locations())
    for c in candidates:
        if c.name.lower() == "clamscan.exe" and c.is_file():
            return c
    return None


@dataclass(frozen=True)
class ClamLine:
    kind: str  # OK | FOUND | ERROR
    signature: str | None = None
    message: str | None = None
    raw: str = ""


def parse_version(text: str) -> tuple[str | None, str | None, str | None]:
    """Return (engine_version, db_version, db_date) from `clamscan --version`."""
    m = _VERSION_RE.match(text.strip())
    if not m:
        return None, None, None
    return m.group("engine"), m.group("db"), (m.group("date") or "").strip() or None


def parse_scan_output(stdout: str) -> dict[str, ClamLine]:
    """Map normalized path -> result line. Unknown lines (warnings, banners) are ignored."""
    results: dict[str, ClamLine] = {}
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if line.startswith("----------- SCAN SUMMARY"):
            break
        if line.endswith(" FOUND") and ": " in line:
            path, sig = line[: -len(" FOUND")].rsplit(": ", 1)
            results[norm_path(path)] = ClamLine("FOUND", signature=sig.strip(), raw=line)
        elif line.endswith(": OK"):
            results[norm_path(line[: -len(": OK")])] = ClamLine("OK", raw=line)
        elif line.endswith(": Empty file"):
            results[norm_path(line[: -len(": Empty file")])] = ClamLine("OK", message="Empty file", raw=line)
        elif line.endswith(" ERROR") and ": " in line:
            path, msg = line[: -len(" ERROR")].rsplit(": ", 1)
            results[norm_path(path)] = ClamLine("ERROR", message=msg.strip(), raw=line)
    return results


def classify_signature(sig: str) -> tuple[Severity, str]:
    if sig.startswith("PUA."):
        return Severity.MEDIUM, f"ClamAV 判定為潛在不受歡迎程式（PUA）：{sig}。PUA 不一定是惡意程式。"
    if sig.startswith("Heuristics."):
        return Severity.MEDIUM, f"ClamAV 啟發式規則命中：{sig}。啟發式偵測可能誤判，需搭配其他證據。"
    return Severity.HIGH, f"ClamAV 病毒碼比對命中：{sig}。病毒碼比對可信度較高，但仍可能誤判。"


def result_from_line(
    t: ScanTarget,
    line: ClamLine | None,
    st: EngineStatus,
    ms: int | None,
    *,
    missing_hint: str = "",
    backend: str,
) -> DetectionResult:
    """Shared mapping from one ClamAV result line to a DetectionResult (both backends)."""
    base = dict(engine_name=ENGINE_NAME, engine_version=st.version, rules_version=st.rules_version,
                duration_ms=ms, info={"backend": backend})
    if line is None:
        return DetectionResult(kind=EngineOutcomeKind.ERROR, error=f"ClamAV 未回報此檔案的結果{missing_hint}", **base)
    if line.kind == "ERROR":
        return DetectionResult(kind=EngineOutcomeKind.ERROR, error=f"ClamAV 無法掃描：{line.message}", **base)
    if line.kind == "OK":
        return DetectionResult(kind=EngineOutcomeKind.NO_FINDINGS, **base)
    sig = line.signature or "unknown"
    if sig.startswith(LIMIT_SIGNATURE_PREFIX):
        return DetectionResult(kind=EngineOutcomeKind.ERROR, error=f"超過 ClamAV 掃描上限，未完整掃描（{sig}）", **base)
    severity, explanation = classify_signature(sig)
    det = DetectionRecord(
        engine_name=ENGINE_NAME,
        engine_version=st.version,
        rule_id=sig,
        severity_hint=severity,
        evidence={"signature": sig, "engine_output": line.raw, "rules_version": st.rules_version,
                  "backend": backend},
        file_sha256=t.sha256,
        confidence_explanation=explanation,
    )
    return DetectionResult(kind=EngineOutcomeKind.FINDINGS, detections=(det,), **base)


class ClamAVEngine:
    """ClamAV via `clamscan.exe` (default backend)."""

    name = ENGINE_NAME

    def __init__(
        self,
        executable: Path | None,
        *,
        timeout_s: int = 120,
        max_file_size_mb: int = 100,
        database_dir: Path | None = None,
        launcher: Sequence[str] | None = None,
    ) -> None:
        """`launcher` replaces the executable invocation (tests use a fake clamscan script)."""
        self._exe = executable
        self._timeout_s = timeout_s
        self._max_mb = max_file_size_mb
        self._db_dir = database_dir
        self._launcher = list(launcher) if launcher else None
        self._status: EngineStatus | None = None

    @property
    def database_dir(self) -> Path | None:
        return self._db_dir

    def set_database_dir(self, path: Path | None) -> None:
        """Used after Sentinel X downloaded signatures into its own folder."""
        self._db_dir = path
        self._status = None

    @property
    def executable(self) -> Path | None:
        return self._exe

    def _cmd(self, *args: str) -> list[str]:
        db = [f"--database={self._db_dir}"] if self._db_dir is not None else []
        if self._launcher:
            return [*self._launcher, *db, *args]
        assert self._exe is not None
        return [str(self._exe), *db, *args]

    def availability(self, refresh: bool = False) -> EngineStatus:
        if self._status is not None and not refresh:
            return self._status
        self._status = self._probe()
        return self._status

    def _probe(self) -> EngineStatus:
        if not self._launcher and (self._exe is None or not self._exe.is_file()):
            return EngineStatus(ENGINE_NAME, False, detail="找不到 clamscan.exe，ClamAV 尚未安裝或路徑設定錯誤。")
        if self._db_dir is not None and not self._db_dir.is_dir():
            return EngineStatus(ENGINE_NAME, False, detail=f"尚未下載病毒碼（資料夾不存在：{self._db_dir}）。"
                                                           "可在「設定 → ClamAV 病毒碼」更新。")
        try:
            cp = subprocess.run(
                self._cmd("--version"),
                capture_output=True,
                timeout=20,
                creationflags=_CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return EngineStatus(ENGINE_NAME, False, detail=f"無法執行 clamscan：{exc}")
        out = cp.stdout.decode("utf-8", "replace").strip()
        engine, db, date = parse_version(out)
        if cp.returncode != 0 or engine is None:
            return EngineStatus(ENGINE_NAME, False, detail=f"clamscan 版本資訊無法解析：{out[:200]!r}")
        if db is None:
            return EngineStatus(
                ENGINE_NAME, False, version=engine,
                detail="找不到 ClamAV 病毒碼資料庫，請先執行 freshclam 更新病毒碼。",
            )
        return EngineStatus(ENGINE_NAME, True, version=engine, rules_version=db, rules_date=date)

    def _error_all(self, targets: Sequence[ScanTarget], msg: str, status: EngineStatus, ms: int | None = None) -> dict[ScanTarget, DetectionResult]:
        return {
            t: DetectionResult(ENGINE_NAME, EngineOutcomeKind.ERROR, status.version, status.rules_version, error=msg, duration_ms=ms)
            for t in targets
        }

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        if not targets:
            return {}
        status = self.availability()
        if not status.available:
            return self._error_all(targets, status.detail, status)

        # clamscan 1.5 on Windows reads a UTF-8 file list correctly, CJK names included
        # (verified against the real engine; see tests/integration/test_clamav_real.py).
        lines = [str(t.path) for t in targets]

        fd, list_path = tempfile.mkstemp(prefix="sx-clam-", suffix=".txt")
        started = time.monotonic()
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(lines) + "\n")
            mb = self._max_mb + 1
            cmd = self._cmd(
                "--no-summary", "--stdout", f"--file-list={list_path}",
                f"--max-filesize={mb}M", f"--max-scansize={mb * 4}M", "--alert-exceeds-max=yes",
            )
            timeout = self._timeout_s + 2 * len(targets)
            code, stdout, stderr = self._run(cmd, timeout, cancel)
        finally:
            try:
                os.remove(list_path)
            except OSError:
                log.warning("could not remove clamscan file list", extra={"ctx": {"path": list_path}})
        ms = int((time.monotonic() - started) * 1000)

        if code is None:
            return self._error_all(targets, f"ClamAV 逾時（{timeout} 秒），未完成掃描。", status, ms)
        if code not in (0, 1, 2):
            return self._error_all(targets, f"ClamAV 異常結束（代碼 {code}）：{stderr[-300:]}", status, ms)

        parsed = parse_scan_output(stdout)
        hint = f"（結束代碼 {code}）{stderr[-200:]}" if stderr else f"（結束代碼 {code}）"
        return {
            t: result_from_line(t, parsed.get(norm_path(t.path)), status, ms, missing_hint=hint, backend="clamscan")
            for t in targets
        }

    def _run(self, cmd: list[str], timeout: int, cancel: CancelToken) -> tuple[int | None, str, str]:
        """Run with polling so cancellation is noticed within ~0.2 s. Returns (code|None on timeout, out, err)."""
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_CREATE_NO_WINDOW
        )
        deadline = time.monotonic() + timeout
        out_b = err_b = b""
        while True:
            try:
                out_b, err_b = proc.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                if cancel.cancelled:
                    proc.kill()
                    proc.communicate()
                    raise ScanCancelled() from None
                if time.monotonic() > deadline:
                    proc.kill()
                    proc.communicate()
                    return None, "", ""
        return proc.returncode, out_b.decode("utf-8", "replace"), err_b.decode("utf-8", "replace")
