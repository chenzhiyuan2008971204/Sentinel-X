"""Normalized security events (facts only; interpretation happens in correlation)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sentinelx.core.enums import EventSource


class EventKind(StrEnum):
    PROCESS_CREATE = "PROCESS_CREATE"
    NET_CONNECT = "NET_CONNECT"
    FILE_CREATE = "FILE_CREATE"
    FILE_MODIFY = "FILE_MODIFY"
    FILE_DELETE = "FILE_DELETE"
    FILE_MOVE = "FILE_MOVE"
    AV_DETECTION = "AV_DETECTION"  # another product (Defender) reported a detection


KIND_TEXT = {
    EventKind.PROCESS_CREATE: "程序啟動",
    EventKind.NET_CONNECT: "網路連線",
    EventKind.FILE_CREATE: "檔案建立",
    EventKind.FILE_MODIFY: "檔案修改",
    EventKind.FILE_DELETE: "檔案刪除",
    EventKind.FILE_MOVE: "檔案移動",
    EventKind.AV_DETECTION: "防毒偵測",
}


@dataclass(frozen=True)
class SecurityEventIn:
    source: EventSource
    kind: EventKind
    occurred_at: str  # UTC ISO
    process_name: str | None = None
    process_path: str | None = None
    pid: int | None = None
    ppid: int | None = None
    command_line: str | None = None
    target_path: str | None = None
    remote_addr: str | None = None
    remote_port: int | None = None
    sha256: str | None = None
    raw_ref: str | None = None
    details: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class StoredEvent(SecurityEventIn):
    id: int = 0
