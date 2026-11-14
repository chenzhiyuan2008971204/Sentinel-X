"""ClamAV adapter, `clamd` backend.

Talks to a running clamd over TCP using the documented null-terminated (`z`) commands:
`zVERSION` for availability and `zINSTREAM` to stream file bytes. Streaming instead of
`SCAN <path>` means clamd never needs access to the user's files and path encoding does
not matter.

Security: the host must be a loopback address (re-checked here even though the config
validator already enforces it), so file contents never leave the machine.

Same error rules as the clamscan backend (shared `result_from_line`): connection problems,
size-limit replies, unparseable replies and timeouts are ERROR, never "no findings".
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from collections.abc import Sequence
from pathlib import Path

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import EngineOutcomeKind
from sentinelx.core.models import DetectionResult, EngineStatus, ScanTarget
from sentinelx.engines.clamav import ENGINE_NAME, ClamLine, parse_version, result_from_line

CHUNK_SIZE = 64 * 1024
MAX_REPLY = 64 * 1024


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_instream_reply(reply: str) -> ClamLine | None:
    """`stream: OK` | `stream: <sig> FOUND` | `... ERROR`. None when unrecognized."""
    r = reply.strip().rstrip("\0").strip()
    if r.startswith("stream: "):
        body = r[len("stream: "):]
        if body == "OK":
            return ClamLine("OK", raw=r)
        if body.endswith(" FOUND"):
            return ClamLine("FOUND", signature=body[: -len(" FOUND")].strip(), raw=r)
        if body.endswith(" ERROR"):
            return ClamLine("ERROR", message=body[: -len(" ERROR")].strip(), raw=r)
        return None
    if r.endswith("ERROR"):
        return ClamLine("ERROR", message=r[: -len("ERROR")].strip(" ."), raw=r)
    return None


class ClamdEngine:
    name = ENGINE_NAME

    def __init__(self, host: str = "127.0.0.1", port: int = 3310, *, timeout_s: int = 120) -> None:
        if not is_loopback(host):
            raise ValueError("clamd host must be a loopback address")
        self._addr = (host, port)
        self._timeout = timeout_s
        self._status: EngineStatus | None = None

    # ---- protocol helpers ----
    def _connect(self) -> socket.socket:
        return socket.create_connection(self._addr, timeout=self._timeout)

    @staticmethod
    def _read_reply(sock: socket.socket) -> str:
        buf = bytearray()
        while b"\0" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REPLY:
                raise OSError("clamd reply too long")
        return bytes(buf).split(b"\0", 1)[0].decode("utf-8", "replace")

    # ---- engine interface ----
    def availability(self, refresh: bool = False) -> EngineStatus:
        if self._status is not None and not refresh:
            return self._status
        self._status = self._probe()
        return self._status

    def _probe(self) -> EngineStatus:
        where = f"{self._addr[0]}:{self._addr[1]}"
        try:
            with self._connect() as s:
                s.sendall(b"zVERSION\0")
                reply = self._read_reply(s)
        except OSError as exc:
            return EngineStatus(ENGINE_NAME, False, detail=f"無法連線到 clamd（{where}）：{exc}。請確認 clamd 已啟動。")
        engine, db, date = parse_version(reply)
        if engine is None:
            return EngineStatus(ENGINE_NAME, False, detail=f"clamd 版本資訊無法解析：{reply[:200]!r}")
        if db is None:
            return EngineStatus(ENGINE_NAME, False, version=engine, detail="clamd 沒有載入病毒碼資料庫。")
        return EngineStatus(ENGINE_NAME, True, version=engine, rules_version=db, rules_date=date,
                            detail=f"clamd {where}")

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        st = self.availability()
        out: dict[ScanTarget, DetectionResult] = {}
        for t in targets:
            cancel.raise_if_cancelled()
            if not st.available:
                out[t] = DetectionResult(ENGINE_NAME, EngineOutcomeKind.ERROR, st.version, st.rules_version,
                                         error=st.detail, info={"backend": "clamd"})
                continue
            started = time.monotonic()
            try:
                reply = self._instream(t.path, cancel)
            except ScanCancelled:
                raise
            except OSError as exc:
                out[t] = DetectionResult(ENGINE_NAME, EngineOutcomeKind.ERROR, st.version, st.rules_version,
                                         error=f"clamd 掃描失敗：{exc}", info={"backend": "clamd"})
                continue
            ms = int((time.monotonic() - started) * 1000)
            line = parse_instream_reply(reply)
            out[t] = result_from_line(t, line, st, ms, missing_hint=f"（無法解析的回應：{reply[:120]!r}）",
                                      backend="clamd")
        return out

    def _instream(self, path: Path, cancel: CancelToken) -> str:
        with self._connect() as s, open(path, "rb") as f:
            s.sendall(b"zINSTREAM\0")
            while chunk := f.read(CHUNK_SIZE):
                if cancel.cancelled:
                    raise ScanCancelled()
                s.sendall(struct.pack("!L", len(chunk)) + chunk)
            s.sendall(struct.pack("!L", 0))
            return self._read_reply(s)
