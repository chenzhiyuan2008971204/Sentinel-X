"""Test doubles and harmless sample generators. No real malware anywhere."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget

# Harmless marker strings the fake engines react to.
MALWARE_MARKER = b"SX-TEST-MALWARE-MARKER"
ENGINE_ERROR_MARKER = b"SX-TEST-ENGINE-ERROR"
LIMITS_MARKER = b"SX-TEST-LIMITS"

FAKE_CLAMSCAN = Path(__file__).parent / "data" / "fake_clamscan.py"


def eicar_bytes() -> bytes:
    """The standard EICAR test string, assembled at runtime so it is never stored in the repo."""
    part1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    part2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    return (part1 + part2).encode("ascii")


def fake_clamscan_launcher() -> list[str]:
    return [sys.executable, "-I", str(FAKE_CLAMSCAN)]


class FakeEngine:
    """In-process engine: flags MALWARE_MARKER, errors on ENGINE_ERROR_MARKER."""

    def __init__(
        self,
        name: str = "FakeAV",
        *,
        available: bool = True,
        raise_on_scan: Exception | None = None,
        omit_results: bool = False,
        delay_per_file_s: float = 0.0,
    ) -> None:
        self.name = name
        self._available = available
        self._raise = raise_on_scan
        self._omit = omit_results
        self._delay = delay_per_file_s
        self.calls = 0
        self.scanned: list[Path] = []
        self.started = threading.Event()

    def availability(self, refresh: bool = False) -> EngineStatus:
        if self._available:
            return EngineStatus(self.name, True, version="9.9", rules_version="42", rules_date="2026-11-01")
        return EngineStatus(self.name, False, detail="測試用：引擎不可用")

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        self.calls += 1
        self.started.set()
        if self._raise is not None:
            raise self._raise
        out: dict[ScanTarget, DetectionResult] = {}
        for t in targets:
            if self._delay:
                end = time.monotonic() + self._delay
                while time.monotonic() < end:
                    cancel.raise_if_cancelled()
                    time.sleep(0.01)
            self.scanned.append(t.path)
            if self._omit:
                continue
            data = t.path.read_bytes()
            if ENGINE_ERROR_MARKER in data:
                out[t] = DetectionResult(self.name, EngineOutcomeKind.ERROR, "9.9", "42", error="測試用引擎錯誤")
            elif MALWARE_MARKER in data:
                det = DetectionRecord(self.name, "9.9", "Test.Marker", Severity.HIGH,
                                      {"marker": MALWARE_MARKER.decode()}, t.sha256, "測試標記命中")
                out[t] = DetectionResult(self.name, EngineOutcomeKind.FINDINGS, "9.9", "42", (det,))
            else:
                out[t] = DetectionResult(self.name, EngineOutcomeKind.NO_FINDINGS, "9.9", "42")
        return out


class SignatureAV:
    """Behaves like ClamAV (same engine name, so graded as a signature engine) for marker files."""

    name = "ClamAV"

    def availability(self, refresh: bool = False) -> EngineStatus:
        return EngineStatus("ClamAV", True, version="1.5.4", rules_version="1")

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        out = {}
        for t in targets:
            if MALWARE_MARKER in t.path.read_bytes():
                d = DetectionRecord("ClamAV", "1.5.4", "Sentinel.Test.Marker-1", Severity.HIGH, {}, t.sha256, "sig")
                out[t] = DetectionResult("ClamAV", EngineOutcomeKind.FINDINGS, "1.5.4", "1", (d,))
            else:
                out[t] = DetectionResult("ClamAV", EngineOutcomeKind.NO_FINDINGS, "1.5.4", "1")
        return out


class FakeCollector:
    """Scripted telemetry source for monitor tests."""

    def __init__(self, name: str = "Fake", *, available: bool = True, requires_admin: bool = False,
                 source=None) -> None:  # type: ignore[no-untyped-def]
        from sentinelx.core.enums import EventSource

        self.name = name
        self.source = source or EventSource.PSUTIL
        self._available = available
        self._admin = requires_admin
        self.pending: list = []  # type: ignore[type-arg]
        self.started = self.stopped = False

    def status(self):  # type: ignore[no-untyped-def]
        from sentinelx.monitor.collectors import CollectorStatus

        detail = "fake" if self._available else ("需要系統管理員" if self._admin else "不可用")
        return CollectorStatus(self.name, self.source, self._available, detail, self._admin)

    def start(self) -> None:
        self.started = True

    def poll(self):  # type: ignore[no-untyped-def]
        out, self.pending = self.pending, []
        return out

    def stop(self) -> None:
        self.stopped = True


class FakeClamd:
    """Minimal clamd speaking zVERSION / zINSTREAM on 127.0.0.1, for contract tests.

    mode: normal | nodb | garbage | sizelimit | drop
    Flags MALWARE_MARKER as Sentinel.Test.Marker-1 and LIMITS_MARKER as Heuristics.Limits.Exceeded.
    """

    def __init__(self, mode: str = "normal") -> None:
        import socket

        self.mode = mode
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn) -> None:  # type: ignore[no-untyped-def]
        import struct

        with conn:
            conn.settimeout(5)
            cmd = b""
            while not cmd.endswith(b"\0"):
                b = conn.recv(1)
                if not b:
                    return
                cmd += b
            if cmd == b"zVERSION\0":
                v = "ClamAV 1.5.4" if self.mode == "nodb" else "ClamAV 1.5.4/27800/Sun Nov  1 09:00:00 2026"
                conn.sendall(v.encode() + b"\0")
                return
            if cmd != b"zINSTREAM\0":
                conn.sendall(b"UNKNOWN COMMAND\0")
                return
            data = bytearray()
            while True:
                hdr = b""
                while len(hdr) < 4:
                    chunk = conn.recv(4 - len(hdr))
                    if not chunk:
                        return
                    hdr += chunk
                (n,) = struct.unpack("!L", hdr)
                if n == 0:
                    break
                while n:
                    chunk = conn.recv(min(n, 65536))
                    if not chunk:
                        return
                    data += chunk
                    n -= len(chunk)
            if self.mode == "drop":
                return
            if self.mode == "garbage":
                conn.sendall(b"what\0")
            elif self.mode == "sizelimit":
                conn.sendall(b"INSTREAM size limit exceeded. ERROR\0")
            elif eicar_bytes()[:20] in data:
                conn.sendall(b"stream: Eicar-Test-Signature FOUND\0")
            elif LIMITS_MARKER in data:
                conn.sendall(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0")
            elif MALWARE_MARKER in data:
                conn.sendall(b"stream: Sentinel.Test.Marker-1 FOUND\0")
            else:
                conn.sendall(b"stream: OK\0")

    def close(self) -> None:
        self._stop.set()
        self._srv.close()
        self._thread.join(2)


def make_tree(root: Path) -> dict[str, Path]:
    """Small harmless sample tree used by several tests."""
    (root / "sub" / "deeper").mkdir(parents=True)
    files = {
        "clean": root / "clean.txt",
        "bad": root / "sub" / "bad.bin",
        "deep": root / "sub" / "deeper" / "note.md",
        "cjk": root / "中文資料夾" / "報告.txt",
    }
    files["cjk"].parent.mkdir()
    files["clean"].write_bytes(b"hello world")
    files["bad"].write_bytes(b"prefix " + MALWARE_MARKER + b" suffix")
    files["deep"].write_bytes(b"# notes")
    files["cjk"].write_bytes("中文內容".encode())
    return files
